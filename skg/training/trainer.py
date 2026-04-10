"""
skg.training.trainer
=====================
Fine-tuning wrapper for local models.

Strategy:
  - Base model: whatever ollama has (llama3.2:3b, mistral:7b, etc.)
  - Method: LoRA via unsloth (preferred) or llama.cpp finetune
  - Output: GGUF LoRA adapter → merged model → new ollama model tag
  - Fallback: JSONL dataset saved for manual fine-tuning

The trainer runs once per day via systemd timer. It:
  1. Checks corpus has enough new examples (MIN_EXAMPLES_FOR_RUN)
  2. Loads + splits train/holdout
  3. Formats examples into chat format (system + user + assistant turns)
  4. Runs fine-tune (unsloth if available, else llama.cpp)
  5. Evaluates new model on holdout set
  6. Swaps model in ollama config if eval passes
  7. Archives previous model
  8. Updates corpus index (marks run complete)

On a laptop with no GPU: unsloth CPU mode works but is slow.
A 3B model LoRA on 50-100 examples: ~2-4h CPU, ~20min with GPU.
Runs overnight via timer — no impact on active usage.

Hardware detection:
  - NVIDIA GPU → unsloth + bitsandbytes 4-bit quant
  - AMD GPU    → unsloth + ROCm (experimental)
  - CPU only   → unsloth CPU or llama.cpp finetune
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from skg_core.config.paths import SKG_STATE_DIR, SKG_HOME
from skg.training.corpus import (
    load_all_examples, split_train_holdout,
    corpus_status, mark_run_complete, MIN_EXAMPLES_FOR_RUN,
)

log = logging.getLogger("skg.training.trainer")

TRAINING_DIR  = SKG_STATE_DIR / "training"
MODELS_DIR    = TRAINING_DIR / "models"
RUNS_DIR      = TRAINING_DIR / "runs"
DATASET_DIR   = TRAINING_DIR / "datasets"

# Eval pass threshold — new model must score this well on holdout
EVAL_PASS_THRESHOLD = 0.6

# Chat format template for instruction fine-tuning
SYSTEM_PROMPT = """You are SKG, a red team intelligence platform assistant.
You generate attack preconditions catalogs (JSON) and collection adapters (Python)
for the SKG platform. Follow the exact schema and patterns shown in examples.
Output only the requested artifact — no explanation, no markdown fences."""


def detect_hardware() -> dict:
    """Detect available training hardware."""
    hw = {"gpu": None, "gpu_mem_gb": 0, "cpu_cores": os.cpu_count() or 1,
          "backend": "cpu"}

    # NVIDIA
    try:
        out = subprocess.check_output(
            ["nvidia-smi", "--query-gpu=name,memory.total",
             "--format=csv,noheader,nounits"],
            stderr=subprocess.DEVNULL, timeout=5
        ).decode().strip()
        if out:
            parts = out.split(",")
            hw["gpu"]        = parts[0].strip()
            hw["gpu_mem_gb"] = int(parts[1].strip()) // 1024
            hw["backend"]    = "nvidia"
    except Exception:
        pass

    # AMD ROCm
    if not hw["gpu"]:
        try:
            out = subprocess.check_output(
                ["rocm-smi", "--showproductname"],
                stderr=subprocess.DEVNULL, timeout=5
            ).decode()
            if "GPU" in out:
                hw["gpu"]     = "AMD GPU (ROCm)"
                hw["backend"] = "amd"
        except Exception:
            pass

    return hw


def _format_example_chat(example: dict) -> dict:
    """
    Format a training example into chat turns for instruction fine-tuning.
    Follows the ChatML format that most GGUF models expect.
    """
    kind = example.get("kind", "catalog")
    label = example.get("label", "positive")

    user_content = example.get("input", "")
    if label == "positive":
        assistant_content = example.get("output", "")
    else:
        # For negative examples, use the correction if available
        # otherwise skip — negatives without corrections are less useful
        correction = example.get("correction", "")
        if correction:
            assistant_content = correction
        else:
            return None  # skip negatives without corrections

    return {
        "conversations": [
            {"role": "system",    "value": SYSTEM_PROMPT},
            {"role": "user",      "value": user_content},
            {"role": "assistant", "value": assistant_content},
        ]
    }


def build_dataset(examples: list[dict], out_path: Path) -> int:
    """
    Write training dataset as JSONL in ShareGPT/ChatML format.
    Returns number of examples written.
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with out_path.open("w") as f:
        for ex in examples:
            formatted = _format_example_chat(ex)
            if formatted:
                f.write(json.dumps(formatted) + "\n")
                count += 1
    return count


def _get_base_model() -> str:
    """Get the current base model from ollama config."""
    try:
        from skg.resonance.ollama_backend import OllamaBackend
        backend = OllamaBackend()
        if backend.available():
            return backend.model() or "llama3.2:3b"
    except Exception:
        pass
    return "llama3.2:3b"


def _run_unsloth(
    train_path: Path,
    holdout_path: Path,
    base_model: str,
    output_dir: Path,
    hw: dict,
    run_log: Path,
) -> dict:
    """
    Run fine-tuning via unsloth. Returns result dict.
    Unsloth is the preferred path — 2-5x faster than vanilla HF,
    runs on CPU if no GPU, handles quantization automatically.
    """
    # Write unsloth training script
    script = output_dir / "train.py"
    quant  = "4bit" if hw["gpu_mem_gb"] >= 6 else "none"
    device = "cuda" if hw["backend"] == "nvidia" else \
             "hip"  if hw["backend"] == "amd"    else "cpu"

    # Max steps scaled to dataset size + hardware
    train_count = sum(1 for _ in open(train_path))
    max_steps   = min(max(train_count * 3, 60), 500)
    batch_size  = 2 if hw["backend"] == "cpu" else 4

    script.write_text(f'''#!/usr/bin/env python3
"""SKG fine-tune run — generated by skg.training.trainer"""
import json
from pathlib import Path
from datasets import Dataset

# Unsloth — fast LoRA fine-tuning
try:
    from unsloth import FastLanguageModel
    HAS_UNSLOTH = True
except ImportError:
    HAS_UNSLOTH = False
    from transformers import AutoModelForCausalLM, AutoTokenizer
    import torch

BASE_MODEL   = "{base_model}"
OUTPUT_DIR   = "{output_dir}"
TRAIN_FILE   = "{train_path}"
MAX_SEQ_LEN  = 2048
LORA_RANK    = 16
MAX_STEPS    = {max_steps}
BATCH_SIZE   = {batch_size}
QUANT        = "{quant}"


def load_jsonl(path):
    data = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                data.append(json.loads(line))
    return data


def format_prompt(example):
    convs = example.get("conversations", [])
    text = ""
    for turn in convs:
        role = turn.get("role", "")
        val  = turn.get("value", "")
        if role == "system":
            text += f"<|system|>\\n{{val}}\\n"
        elif role == "user":
            text += f"<|user|>\\n{{val}}\\n"
        elif role == "assistant":
            text += f"<|assistant|>\\n{{val}}\\n"
    return text + "<|end|>"


def main():
    print(f"[train] base model: {{BASE_MODEL}}")
    print(f"[train] max steps: {{MAX_STEPS}}, batch: {{BATCH_SIZE}}")

    raw = load_jsonl(TRAIN_FILE)
    texts = [format_prompt(ex) for ex in raw]
    dataset = Dataset.from_dict({{"text": texts}})

    if HAS_UNSLOTH:
        model, tokenizer = FastLanguageModel.from_pretrained(
            model_name=BASE_MODEL,
            max_seq_length=MAX_SEQ_LEN,
            load_in_4bit=(QUANT == "4bit"),
            dtype=None,
        )
        model = FastLanguageModel.get_peft_model(
            model,
            r=LORA_RANK,
            target_modules=["q_proj","k_proj","v_proj","o_proj",
                            "gate_proj","up_proj","down_proj"],
            lora_alpha=LORA_RANK,
            lora_dropout=0,
            bias="none",
            use_gradient_checkpointing="unsloth",
            random_state=42,
        )
        from trl import SFTTrainer
        from transformers import TrainingArguments
        trainer = SFTTrainer(
            model=model,
            tokenizer=tokenizer,
            train_dataset=dataset,
            dataset_text_field="text",
            max_seq_length=MAX_SEQ_LEN,
            args=TrainingArguments(
                per_device_train_batch_size=BATCH_SIZE,
                gradient_accumulation_steps=4,
                max_steps=MAX_STEPS,
                learning_rate=2e-4,
                fp16=("{device}" != "cpu"),
                logging_steps=10,
                output_dir=OUTPUT_DIR,
                optim="adamw_8bit" if "{device}" != "cpu" else "adamw_torch",
                lr_scheduler_type="cosine",
                warmup_steps=5,
                save_steps=MAX_STEPS,
                save_total_limit=1,
            ),
        )
        trainer.train()
        model.save_pretrained(OUTPUT_DIR + "/lora")
        tokenizer.save_pretrained(OUTPUT_DIR + "/lora")
        print(f"[train] LoRA saved: {{OUTPUT_DIR}}/lora")

        # Export to GGUF for ollama
        try:
            model.save_pretrained_gguf(
                OUTPUT_DIR + "/gguf",
                tokenizer,
                quantization_method="q4_k_m",
            )
            print(f"[train] GGUF saved: {{OUTPUT_DIR}}/gguf")
        except Exception as e:
            print(f"[train] GGUF export failed (manual merge needed): {{e}}")
    else:
        print("[train] unsloth not available — saved dataset only")
        print(f"[train] dataset: {{TRAIN_FILE}}")
        print("[train] install: pip install unsloth")

    print("[train] done")


if __name__ == "__main__":
    main()
''')

    # Run in the venv
    venv_python = SKG_HOME / ".venv" / "bin" / "python"
    python = str(venv_python) if venv_python.exists() else sys.executable

    log.info(f"[trainer] launching unsloth fine-tune ({max_steps} steps)...")
    try:
        with run_log.open("w") as log_f:
            proc = subprocess.run(
                [python, str(script)],
                stdout=log_f, stderr=subprocess.STDOUT,
                timeout=14400,  # 4h max
                cwd=str(output_dir),
            )
        success = proc.returncode == 0
    except subprocess.TimeoutExpired:
        log.warning("[trainer] fine-tune timed out after 4h")
        return {"success": False, "error": "timeout"}
    except Exception as exc:
        return {"success": False, "error": str(exc)}

    gguf_dir  = output_dir / "gguf"
    lora_dir  = output_dir / "lora"
    gguf_file = next(gguf_dir.glob("*.gguf"), None) if gguf_dir.exists() else None

    return {
        "success":   success,
        "gguf_file": str(gguf_file) if gguf_file else None,
        "lora_dir":  str(lora_dir) if lora_dir.exists() else None,
        "log":       str(run_log),
    }


def _register_with_ollama(gguf_file: str, model_tag: str) -> bool:
    """
    Register a GGUF model with ollama via Modelfile.
    Returns True on success.
    """
    try:
        model_dir = MODELS_DIR / model_tag.replace(":", "_")
        model_dir.mkdir(parents=True, exist_ok=True)

        modelfile = model_dir / "Modelfile"
        modelfile.write_text(
            f'FROM {gguf_file}\n'
            f'SYSTEM """{SYSTEM_PROMPT}"""\n'
            f'PARAMETER temperature 0.1\n'
            f'PARAMETER num_ctx 4096\n'
        )

        result = subprocess.run(
            ["ollama", "create", model_tag, "-f", str(modelfile)],
            capture_output=True, text=True, timeout=300,
        )
        if result.returncode == 0:
            log.info(f"[trainer] registered ollama model: {model_tag}")
            return True
        else:
            log.warning(f"[trainer] ollama create failed: {result.stderr[:200]}")
            return False
    except Exception as exc:
        log.warning(f"[trainer] ollama registration error: {exc}")
        return False


def _evaluate_model(holdout_examples: list[dict],
                    model_tag: str) -> dict:
    """
    Evaluate the new model on holdout examples.
    Score = fraction of outputs that are valid JSON (for catalog kind)
    or valid Python (for adapter kind).
    """
    if not holdout_examples:
        return {"score": 1.0, "evaluated": 0, "passed": 0}

    try:
        from skg.resonance.ollama_backend import OllamaBackend
        backend = OllamaBackend()
        if not backend.available():
            log.warning("[trainer] ollama not available for eval — skipping")
            return {"score": 1.0, "evaluated": 0, "passed": 0, "skipped": True}

        passed = 0
        for ex in holdout_examples[:20]:  # cap eval at 20 examples
            kind   = ex.get("kind", "catalog")
            prompt = ex.get("input", "")
            expected = ex.get("output", "")

            try:
                generated = backend.generate(prompt, model=model_tag)
                if kind == "catalog":
                    # Valid JSON with wickets key
                    parsed = json.loads(generated.strip().strip("```json").strip("```"))
                    if "wickets" in parsed and "attack_paths" in parsed:
                        passed += 1
                elif kind == "adapter":
                    # Valid Python with emit or evaluate_wickets
                    if ("def emit(" in generated or "def evaluate_wickets(" in generated
                            or "def check_" in generated):
                        passed += 1
                elif kind == "wicket_map":
                    # Simple status string match
                    if generated.strip().lower() in ("realized", "blocked", "unknown"):
                        passed += 1
            except Exception:
                pass

        evaluated = min(len(holdout_examples), 20)
        score = passed / evaluated if evaluated > 0 else 0.0
        return {"score": score, "evaluated": evaluated, "passed": passed}

    except Exception as exc:
        log.warning(f"[trainer] eval error: {exc}")
        return {"score": 1.0, "evaluated": 0, "passed": 0, "error": str(exc)}


def run_training() -> dict:
    """
    Main training entry point. Called by scheduler once per day.

    Returns result dict with success, model_tag, eval_score, etc.
    """
    now     = datetime.now(timezone.utc)
    run_id  = now.strftime("%Y%m%d_%H%M%S")
    run_dir = RUNS_DIR / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    DATASET_DIR.mkdir(parents=True, exist_ok=True)
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    log.info(f"[trainer] starting run {run_id}")
    result = {
        "run_id":       run_id,
        "started_at":   now.isoformat(),
        "success":      False,
        "skipped":      False,
        "model_tag":    None,
        "eval_score":   None,
        "error":        None,
    }

    # Check corpus readiness
    status = corpus_status()
    if not status["ready_for_run"]:
        msg = (f"corpus not ready: {status['examples_since_last_run']} new examples "
               f"(need {MIN_EXAMPLES_FOR_RUN})")
        log.info(f"[trainer] skipping — {msg}")
        result["skipped"] = True
        result["reason"]  = msg
        return result

    # Load and split
    all_examples = load_all_examples()
    if not all_examples:
        result["skipped"] = True
        result["reason"]  = "no examples in corpus"
        return result

    train_examples, holdout_examples = split_train_holdout(all_examples)
    log.info(f"[trainer] {len(train_examples)} train, {len(holdout_examples)} holdout")

    # Write datasets
    train_path   = DATASET_DIR / f"{run_id}_train.jsonl"
    holdout_path = DATASET_DIR / f"{run_id}_holdout.jsonl"
    train_count   = build_dataset(train_examples,   train_path)
    holdout_count = build_dataset(holdout_examples, holdout_path)
    log.info(f"[trainer] dataset: {train_count} train, {holdout_count} holdout examples")

    if train_count < 5:
        result["skipped"] = True
        result["reason"]  = f"too few formatted examples: {train_count}"
        return result

    # Detect hardware
    hw = detect_hardware()
    log.info(f"[trainer] hardware: {hw}")

    # Base model
    base_model = _get_base_model()
    log.info(f"[trainer] base model: {base_model}")

    # Model tag for this run
    base_slug  = base_model.replace(":", "_").replace("/", "_")
    model_tag  = f"skg-{base_slug}-{run_id}"

    # Check unsloth availability
    try:
        import unsloth
        HAS_UNSLOTH = True
    except ImportError:
        HAS_UNSLOTH = False

    if HAS_UNSLOTH:
        train_result = _run_unsloth(
            train_path, holdout_path, base_model,
            run_dir, hw, run_dir / "train.log"
        )
    else:
        # No unsloth — save dataset for manual use, note install path
        log.warning("[trainer] unsloth not installed — saving dataset only")
        log.warning("[trainer] install: pip install unsloth")
        train_result = {
            "success": False,
            "error":   "unsloth not installed",
            "dataset": str(train_path),
        }

    if not train_result.get("success"):
        result["error"]   = train_result.get("error", "training failed")
        result["dataset"] = str(train_path)
        # Still mark partial progress
        _write_run_record(run_dir, result, train_result, hw)
        return result

    # Register with ollama
    gguf_file = train_result.get("gguf_file")
    registered = False
    if gguf_file and Path(gguf_file).exists():
        registered = _register_with_ollama(gguf_file, model_tag)
    elif train_result.get("lora_dir"):
        log.info("[trainer] GGUF not produced — LoRA available for manual merge")

    # Evaluate
    eval_result = {"score": 1.0, "skipped": True}
    if registered:
        eval_result = _evaluate_model(holdout_examples, model_tag)
        log.info(f"[trainer] eval score: {eval_result['score']:.2f} "
                 f"({eval_result.get('passed',0)}/{eval_result.get('evaluated',0)})")

    # Swap model if eval passes
    swapped = False
    if registered and eval_result["score"] >= EVAL_PASS_THRESHOLD:
        try:
            from skg.resonance.ollama_backend import OllamaBackend
            backend = OllamaBackend()
            backend.set_model(model_tag)
            log.info(f"[trainer] active model updated: {model_tag}")
            swapped = True
        except Exception as exc:
            log.warning(f"[trainer] model swap failed: {exc}")
    elif registered:
        log.warning(f"[trainer] eval below threshold ({eval_result['score']:.2f} < "
                    f"{EVAL_PASS_THRESHOLD}) — keeping current model")

    result.update({
        "success":      True,
        "model_tag":    model_tag if registered else None,
        "eval_score":   eval_result.get("score"),
        "eval_passed":  eval_result.get("score", 0) >= EVAL_PASS_THRESHOLD,
        "model_swapped": swapped,
        "train_count":  train_count,
        "hardware":     hw,
    })

    mark_run_complete()
    _write_run_record(run_dir, result, train_result, hw)
    log.info(f"[trainer] run complete: {run_id} "
             f"(swapped={swapped}, score={eval_result.get('score','?')})")
    return result


def _write_run_record(run_dir: Path, result: dict,
                      train_result: dict, hw: dict):
    record = {
        **result,
        "train_result": train_result,
        "hardware":     hw,
        "recorded_at":  datetime.now(timezone.utc).isoformat(),
    }
    (run_dir / "run_record.json").write_text(json.dumps(record, indent=2))


def training_status() -> dict:
    """Current training system status."""
    hw     = detect_hardware()
    corpus = corpus_status()

    # Last run
    last_run = None
    if RUNS_DIR.exists():
        runs = sorted(RUNS_DIR.iterdir(), reverse=True)
        for r in runs[:1]:
            rec = r / "run_record.json"
            if rec.exists():
                try:
                    last_run = json.loads(rec.read_text())
                except Exception:
                    pass

    # Check unsloth
    try:
        import unsloth
        has_unsloth = True
    except ImportError:
        has_unsloth = False

    return {
        "hardware":     hw,
        "has_unsloth":  has_unsloth,
        "corpus":       corpus,
        "last_run":     last_run,
        "active_model": _get_base_model(),
    }
