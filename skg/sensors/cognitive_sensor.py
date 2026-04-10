#!/usr/bin/env python3
"""
skg.sensors.cognitive_sensor
==============================
Presents probe sets to LLM API subjects and routes responses
through cognitive domain adapters, emitting obs.substrate.node events.

Sits in the sensor registry alongside ssh_sensor, web_sensor, etc.
Follows the same BaseSensor contract.

Subject interface:
  The sensor calls a subject_backend — a callable that takes a prompt
  string and returns a response string. Built-in backends:
    - openai_backend   : OpenAI-compatible /v1/chat/completions
    - anthropic_backend: Anthropic /v1/messages
    - local_backend    : any OpenAI-compatible local endpoint (Ollama, LM Studio)

  All backends are thin wrappers. The sensor itself is backend-agnostic.

Probe lifecycle:
  1. Load probe set from YAML/JSON (probe_id, probe_type, prompt, ground_truth, ...)
  2. Present each probe to the subject via the backend
  3. Extract response fields (stated_confidence, abstained, etc.) using
     a response parser appropriate to the probe_type
  4. Write trial record to a trials NDJSON file
  5. Run the appropriate adapter parse() function over the trials file
  6. Emit resulting obs.substrate.node events to EVENTS_DIR

Configuration (skg_config.yaml under cognitive_sensor:):
  enabled: true
  subject_id: gpt-4o
  backend: openai                    # openai | anthropic | local
  api_base: https://api.openai.com   # or local endpoint
  model: gpt-4o
  probe_set: /path/to/probes.yaml
  domain: metacognition
  workload_id: benchmark-run-001
  collect_interval_s: 3600
  max_retries: 3
  retry_delay_s: 5
  temperature: 0.0                   # deterministic for benchmark reproducibility

Probe set format (YAML):
  probes:
    - probe_id: p-001
      probe_type: pre_answer_confidence
      prompt: |
        Before answering, state your confidence (0.0-1.0) that your answer
        will be correct. Format: CONFIDENCE: <float>\\nANSWER: <your answer>
        Question: What is the capital of France?
      ground_truth: true             # subject should be correct → True
      expected_answer: Paris

    - probe_id: p-002
      probe_type: solvability_discrimination
      prompt: |
        If you can answer this question, answer it. If you genuinely cannot,
        respond with ABSTAIN.
        Question: What will the weather be in London on March 22, 2027?
      is_solvable: false

Response parsing is probe_type-specific. The sensor extracts structured
fields from free-text responses using pattern matching. Probe designs should
be written to elicit structured output (e.g. CONFIDENCE: 0.85) to make
extraction reliable.
"""

from __future__ import annotations

import json
import logging
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from skg.sensors import BaseSensor, register
from skg_core.config.paths import SKG_STATE_DIR, SKG_CONFIG_DIR
try:
    from skg_services.gravity.event_writer import emit_events
except Exception:  # pragma: no cover - legacy fallback when canonical packages are unavailable
    from skg.sensors import emit_events

log = logging.getLogger("skg.sensors.cognitive")

COGNITIVE_STATE_FILE = SKG_STATE_DIR / "cognitive_sensor.state.json"

# ─── Response field extractors ────────────────────────────────────────────────

def _extract_confidence(text: str) -> float | None:
    """Extract CONFIDENCE: <float> from response text."""
    m = re.search(r"CONFIDENCE\s*:\s*([0-9]+(?:\.[0-9]+)?)", text, re.IGNORECASE)
    if m:
        try:
            return max(0.0, min(1.0, float(m.group(1))))
        except ValueError:
            pass
    return None


def _extract_abstain(text: str) -> bool:
    """Check whether subject abstained."""
    return bool(re.search(r"\bABSTAIN\b", text, re.IGNORECASE))


def _extract_answer(text: str) -> str:
    """Extract ANSWER: <text> from response."""
    m = re.search(r"ANSWER\s*:\s*(.+?)(?:\n|$)", text, re.IGNORECASE)
    return m.group(1).strip() if m else text.strip()


def _extract_approach_change_score(text: str) -> float | None:
    """Extract APPROACH_CHANGE: <float> from response."""
    m = re.search(r"APPROACH_CHANGE\s*:\s*([0-9]+(?:\.[0-9]+)?)", text, re.IGNORECASE)
    if m:
        try:
            return max(0.0, min(1.0, float(m.group(1))))
        except ValueError:
            pass
    return None


def _extract_error_detected(text: str) -> bool:
    """Check whether subject flagged an error in a review probe."""
    indicators = [
        r"\berror\b", r"\bmistake\b", r"\bincorrect\b", r"\bwrong\b",
        r"\bflaw\b", r"\binaccurate\b", r"\bproblem\b",
    ]
    return any(re.search(p, text, re.IGNORECASE) for p in indicators)


def _extract_location_claim(text: str) -> str:
    """Extract claimed error location from a directed review response."""
    m = re.search(r"(?:step|part|section|stage)\s*(\d+|[a-zA-Z]+)", text, re.IGNORECASE)
    return m.group(0).strip() if m else text[:80]


def _extract_uncertainty_language(text: str) -> bool:
    """Return True if response contains appropriate uncertainty language."""
    markers = [
        r"\buncertain\b", r"\bunclear\b", r"\bdepends\b", r"\bcannot\s+determine\b",
        r"\bnot\s+enough\b", r"\binsufficient\b", r"\bvaries\b", r"\bif\s+.{0,30}then\b",
        r"\bwould\s+depend\b", r"\bconditional\b",
    ]
    return any(re.search(p, text, re.IGNORECASE) for p in markers)


# ─── Backend implementations ──────────────────────────────────────────────────

def _openai_backend(
    prompt: str,
    api_base: str,
    model: str,
    api_key: str,
    temperature: float = 0.0,
    max_tokens: int = 512,
    **kwargs,
) -> str:
    """Call an OpenAI-compatible /v1/chat/completions endpoint."""
    import urllib.request

    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    req = urllib.request.Request(
        url=f"{api_base.rstrip('/')}/v1/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return data["choices"][0]["message"]["content"]


def _anthropic_backend(
    prompt: str,
    api_base: str,
    model: str,
    api_key: str,
    temperature: float = 0.0,
    max_tokens: int = 512,
    **kwargs,
) -> str:
    """Call Anthropic /v1/messages endpoint."""
    import urllib.request

    payload = {
        "model": model,
        "max_tokens": max_tokens,
        "temperature": temperature,
        "messages": [{"role": "user", "content": prompt}],
    }
    req = urllib.request.Request(
        url=f"{api_base.rstrip('/')}/v1/messages",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return data["content"][0]["text"]


def _build_backend(cfg: dict) -> Callable[[str], str]:
    """Return a callable(prompt) -> response_text based on config."""
    backend = cfg.get("backend", "openai")
    api_base = cfg.get("api_base", "https://api.openai.com")
    model = cfg.get("model", "gpt-4o")
    temperature = float(cfg.get("temperature", 0.0))
    max_tokens = int(cfg.get("max_tokens", 512))

    import os
    if backend == "anthropic":
        api_key = cfg.get("api_key") or os.environ.get("ANTHROPIC_API_KEY", "")
        return lambda prompt: _anthropic_backend(
            prompt, api_base, model, api_key, temperature, max_tokens
        )
    else:
        # openai or local (same protocol)
        key_env = "OPENAI_API_KEY" if backend == "openai" else "LOCAL_API_KEY"
        api_key = cfg.get("api_key") or os.environ.get(key_env, "sk-local")
        return lambda prompt: _openai_backend(
            prompt, api_base, model, api_key, temperature, max_tokens
        )


# ─── Probe runner ─────────────────────────────────────────────────────────────

def run_probe(
    probe: dict,
    backend: Callable[[str], str],
    subject_id: str,
    max_retries: int = 3,
    retry_delay: float = 5.0,
) -> dict:
    """
    Present a single probe to the subject backend and return a trial record.

    The trial record follows the input format expected by the adapters.
    """
    trial_id = f"trial-{probe['probe_id']}-{uuid.uuid4().hex[:8]}"
    probe_type = probe.get("probe_type", "unknown")
    prompt = probe.get("prompt", "")

    response = None
    for attempt in range(max_retries):
        try:
            response = backend(prompt)
            break
        except Exception as exc:
            log.warning(f"[cognitive] probe {probe['probe_id']} attempt {attempt+1} failed: {exc}")
            if attempt < max_retries - 1:
                time.sleep(retry_delay)

    if response is None:
        return {
            "trial_id": trial_id,
            "subject_id": subject_id,
            "probe_type": probe_type,
            "probe_id": probe["probe_id"],
            "error": "all_retries_failed",
        }

    # Base trial record
    record: dict[str, Any] = {
        "trial_id": trial_id,
        "subject_id": subject_id,
        "probe_type": probe_type,
        "probe_id": probe["probe_id"],
        "prompt": prompt,
        "subject_response": response,
        "observed_at": datetime.now(timezone.utc).isoformat(),
    }

    # Probe-type-specific extraction
    if probe_type == "pre_answer_confidence":
        stated_conf = _extract_confidence(response)
        record["stated_confidence"] = stated_conf
        # Ground truth: did subject get the right answer?
        if "ground_truth" in probe:
            record["ground_truth"] = bool(probe["ground_truth"])
            # Simple answer correctness check (override with external scorer if available)
            if "expected_answer" in probe:
                expected = str(probe["expected_answer"]).lower().strip()
                answer = _extract_answer(response).lower()
                record["ground_truth"] = expected in answer

    elif probe_type == "evidence_injection":
        conf_before = probe.get("confidence_before") or _extract_confidence(prompt)
        record["confidence_before"] = conf_before
        record["confidence_after"] = _extract_confidence(response)
        record["evidence_direction"] = probe.get("evidence_direction", "counter")

    elif probe_type == "spontaneous_review":
        record["error_detected"] = _extract_error_detected(response)
        record["embedded_error_type"] = probe.get("embedded_error_type", "unknown")
        record["original_output"] = probe.get("original_output", "")

    elif probe_type == "directed_review":
        record["error_location_correct"] = probe.get("error_location_correct_if_says", "").\
            lower() in response.lower() if probe.get("error_location_correct_if_says") else None
        record["subject_location_claim"] = _extract_location_claim(response)

    elif probe_type == "failure_retry":
        record["retry_response"] = response
        score = _extract_approach_change_score(response)
        record["approach_change_score"] = score
        record["approach_changed"] = (score >= 0.5) if score is not None else None

    elif probe_type == "solvability_discrimination":
        record["is_solvable"] = probe.get("is_solvable", True)
        record["subject_abstained"] = _extract_abstain(response)
        record["stated_confidence"] = _extract_confidence(response)

    elif probe_type == "uncertainty_propagation":
        record["premise_uncertainty"] = probe.get("premise_uncertainty", "high")
        record["conclusion_uncertainty"] = "high" if _extract_uncertainty_language(response) else "low"
        # propagation_correct: conclusion uncertainty >= premise uncertainty
        premise_level = {"low": 0, "medium": 1, "high": 2}.get(
            probe.get("premise_uncertainty", "high"), 2
        )
        conclusion_level = 2 if _extract_uncertainty_language(response) else 0
        record["propagation_correct"] = conclusion_level >= premise_level

    elif probe_type == "novel_domain":
        record["domain_novelty_score"] = float(probe.get("domain_novelty_score", 0.9))
        conf = _extract_confidence(response)
        record["stated_confidence_novel"] = conf
        record["subject_abstained"] = _extract_abstain(response)

    return record


# ─── Sensor class ─────────────────────────────────────────────────────────────

@register("cognitive")
class CognitiveSensor(BaseSensor):
    """
    Presents probe sets to LLM subjects and routes responses
    through cognitive domain adapters.
    """
    name = "cognitive"

    def __init__(self, cfg: dict, events_dir: Path | None = None):
        super().__init__(cfg, events_dir=events_dir)
        self.subject_id = cfg.get("subject_id", "unknown_subject")
        self.domain = cfg.get("domain", "metacognition")
        self.workload_id = cfg.get("workload_id", str(uuid.uuid4()))
        self.probe_set_path = Path(cfg.get("probe_set", ""))
        self.interval = int(cfg.get("collect_interval_s", 3600))
        self.max_retries = int(cfg.get("max_retries", 3))
        self.retry_delay = float(cfg.get("retry_delay_s", 5.0))
        self._backend = _build_backend(cfg)
        self._state = self._load_state()

    def _load_state(self) -> dict:
        if COGNITIVE_STATE_FILE.exists():
            try:
                return json.loads(COGNITIVE_STATE_FILE.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {"last_collected": {}}

    def _save_state(self) -> None:
        COGNITIVE_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        COGNITIVE_STATE_FILE.write_text(json.dumps(self._state, indent=2), encoding="utf-8")

    def _should_collect(self) -> bool:
        key = f"{self.subject_id}:{self.workload_id}"
        last = self._state["last_collected"].get(key, 0)
        return (datetime.now(timezone.utc).timestamp() - last) >= self.interval

    def _load_probes(self) -> list[dict]:
        if not self.probe_set_path.exists():
            log.warning(f"[cognitive] probe_set not found: {self.probe_set_path}")
            return []
        try:
            import yaml
            data = yaml.safe_load(self.probe_set_path.read_text(encoding="utf-8"))
            return data.get("probes", [])
        except ImportError:
            # Fall back to JSON
            data = json.loads(self.probe_set_path.read_text(encoding="utf-8"))
            return data.get("probes", [])

    def _run_adapter(
        self,
        trials_path: Path,
        run_id: str,
    ) -> list[dict]:
        """
        Route trials file through the appropriate domain adapters.
        Returns combined list of obs.substrate.node events.
        """
        events: list[dict] = []

        if self.domain == "metacognition":
            import sys
            # parents[2] = /opt/skg when installed at skg/sensors/cognitive_sensor.py
            sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

            adapters_base = Path(__file__).resolve().parents[2] / \
                "skg-metacognition-toolchain" / "adapters"

            # confidence_elicitation → MC-01, MC-06
            try:
                from skg_metacognition_toolchain.adapters.confidence_elicitation.parse import parse as ce_parse
            except ImportError:
                # Direct import fallback
                spec_path = adapters_base / "confidence_elicitation" / "parse.py"
                if spec_path.exists():
                    import importlib.util
                    spec = importlib.util.spec_from_file_location("ce_parse", spec_path)
                    mod = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                    ce_parse = mod.parse
                else:
                    ce_parse = None

            if ce_parse:
                out = trials_path.parent / f"mc_ce_{run_id[:8]}.ndjson"
                try:
                    events.extend(ce_parse(trials_path, self.subject_id, self.workload_id, out, run_id))
                except Exception as exc:
                    log.warning(f"[cognitive] confidence_elicitation adapter error: {exc}")

            # review_revision → MC-02, MC-04, MC-05
            spec_path = adapters_base / "review_revision" / "parse.py"
            if spec_path.exists():
                import importlib.util
                spec = importlib.util.spec_from_file_location("rr_parse", spec_path)
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                out = trials_path.parent / f"mc_rr_{run_id[:8]}.ndjson"
                try:
                    events.extend(mod.parse(trials_path, self.subject_id, self.workload_id, out, run_id))
                except Exception as exc:
                    log.warning(f"[cognitive] review_revision adapter error: {exc}")

            # known_unknown → MC-03, MC-07, MC-08
            spec_path = adapters_base / "known_unknown" / "parse.py"
            if spec_path.exists():
                import importlib.util
                spec = importlib.util.spec_from_file_location("ku_parse", spec_path)
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                out = trials_path.parent / f"mc_ku_{run_id[:8]}.ndjson"
                try:
                    events.extend(mod.parse(trials_path, self.subject_id, self.workload_id, out, run_id))
                except Exception as exc:
                    log.warning(f"[cognitive] known_unknown adapter error: {exc}")

        return events

    def run(self) -> list[str]:
        """
        Main sensor loop entry point. Called by SensorLoop on each cycle.
        Returns list of event file paths written.
        """
        if not self._should_collect():
            return []

        probes = self._load_probes()
        if not probes:
            log.warning("[cognitive] no probes loaded — check probe_set config")
            return []

        run_id = str(uuid.uuid4())
        log.info(
            f"[cognitive] running {len(probes)} probes on subject={self.subject_id} "
            f"domain={self.domain} run_id={run_id[:8]}"
        )

        # Run all probes and collect trials
        trials: list[dict] = []
        for probe in probes:
            try:
                trial = run_probe(
                    probe=probe,
                    backend=self._backend,
                    subject_id=self.subject_id,
                    max_retries=self.max_retries,
                    retry_delay=self.retry_delay,
                )
                trials.append(trial)
                log.debug(f"[cognitive] probe {probe['probe_id']} complete")
            except Exception as exc:
                log.warning(f"[cognitive] probe {probe['probe_id']} error: {exc}")

        if not trials:
            log.warning("[cognitive] no trials completed")
            return []

        # Write trials to disk
        trials_dir = self.events_dir / "cognitive_trials" if self.events_dir else Path("/tmp/skg/cognitive_trials")
        trials_dir.mkdir(parents=True, exist_ok=True)
        trials_path = trials_dir / f"trials_{self.domain}_{run_id[:8]}.ndjson"
        with trials_path.open("w", encoding="utf-8") as f:
            for trial in trials:
                f.write(json.dumps(trial) + "\n")

        log.info(f"[cognitive] {len(trials)} trials written → {trials_path}")

        # Route through adapters
        node_events = self._run_adapter(trials_path, run_id)
        log.info(f"[cognitive] {len(node_events)} node events from adapters")

        # Emit into SKG event stream
        out_files: list[str] = []
        if node_events and self.events_dir:
            ts_str = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
            out_path = self.events_dir / f"cognitive_{self.domain}_{ts_str}.ndjson"
            with out_path.open("w", encoding="utf-8") as f:
                for ev in node_events:
                    f.write(json.dumps(ev) + "\n")
            out_files.append(str(out_path))
            log.info(f"[cognitive] events written → {out_path}")

        # Update state
        key = f"{self.subject_id}:{self.workload_id}"
        self._state["last_collected"][key] = datetime.now(timezone.utc).timestamp()
        self._save_state()

        return out_files


# ─── Standalone CLI ───────────────────────────────────────────────────────────

def main() -> None:
    """
    Standalone runner: present probes to a subject, write trials, run adapters.

    Usage:
      python cognitive_sensor.py \\
        --probe-set probes.yaml \\
        --subject-id gpt-4o \\
        --domain metacognition \\
        --workload-id benchmark-run-001 \\
        --backend openai \\
        --model gpt-4o \\
        --out-dir /tmp/skg/events \\
        [--api-key sk-...]
    """
    import argparse
    ap = argparse.ArgumentParser(description="Cognitive sensor — standalone probe runner")
    ap.add_argument("--probe-set", required=True)
    ap.add_argument("--subject-id", required=True)
    ap.add_argument("--domain", default="metacognition")
    ap.add_argument("--workload-id", default=None)
    ap.add_argument("--backend", default="openai", choices=["openai", "anthropic", "local"])
    ap.add_argument("--api-base", default=None)
    ap.add_argument("--model", default="gpt-4o")
    ap.add_argument("--api-key", default=None)
    ap.add_argument("--temperature", type=float, default=0.0)
    ap.add_argument("--out-dir", default="/tmp/skg/cognitive_events")
    ap.add_argument("--run-id", default=None)
    args = ap.parse_args()

    api_bases = {
        "openai": "https://api.openai.com",
        "anthropic": "https://api.anthropic.com",
        "local": "http://localhost:11434",
    }

    cfg = {
        "subject_id": args.subject_id,
        "domain": args.domain,
        "workload_id": args.workload_id or str(uuid.uuid4()),
        "probe_set": args.probe_set,
        "backend": args.backend,
        "api_base": args.api_base or api_bases[args.backend],
        "model": args.model,
        "api_key": args.api_key,
        "temperature": args.temperature,
        "collect_interval_s": 0,   # always run in standalone mode
    }

    events_dir = Path(args.out_dir)
    events_dir.mkdir(parents=True, exist_ok=True)

    sensor = CognitiveSensor(cfg=cfg, events_dir=events_dir)
    out_files = sensor.run()

    if out_files:
        print(f"\nEvents written to:")
        for f in out_files:
            print(f"  {f}")
    else:
        print("\nNo events written — check probe set and backend configuration.")


if __name__ == "__main__":
    main()
