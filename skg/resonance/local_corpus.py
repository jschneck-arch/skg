"""
skg.resonance.local_corpus
==========================
Local knowledge ingestion for resonance corpus memory.

Sources:
  - pearls ledger (structural memory)
  - command --help output
  - man pages
  - local code/docs files
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Iterable

from skg.resonance.memory import CorpusMemory

log = logging.getLogger("skg.resonance.local_corpus")


DEFAULT_HELP_CANDIDATES: tuple[str, ...] = (
    "rg",
    "grep",
    "find",
    "awk",
    "sed",
    "bash",
    "git",
    "python3",
    "pytest",
    "uv",
    "curl",
    "wget",
    "ssh",
    "ss",
    "nmap",
    "docker",
    "podman",
    "systemctl",
    "journalctl",
    "openssl",
    "make",
    "node",
    "npm",
)

DEFAULT_MAN_CANDIDATES: tuple[str, ...] = (
    "bash",
    "sh",
    "find",
    "grep",
    "sed",
    "awk",
    "rg",
    "git",
    "ssh",
    "ss",
    "systemctl",
    "journalctl",
    "man",
    "curl",
    "openssl",
)


def _chunks(text: str, max_chars: int) -> list[str]:
    raw = (text or "").replace("\r", "")
    if not raw.strip():
        return []
    lines = [line.rstrip() for line in raw.splitlines()]
    parts: list[str] = []
    current: list[str] = []
    cur_len = 0
    for line in lines:
        if not line and not current:
            continue
        add = len(line) + 1
        if current and cur_len + add > max_chars:
            parts.append("\n".join(current).strip())
            current = [line]
            cur_len = add
        else:
            current.append(line)
            cur_len += add
    if current:
        parts.append("\n".join(current).strip())
    return [p for p in parts if p]


def _record_id(source_kind: str, source_ref: str, idx: int, chunk: str) -> str:
    digest = hashlib.sha1(
        f"{source_kind}|{source_ref}|{idx}|{chunk}".encode("utf-8", errors="replace")
    ).hexdigest()
    return f"corpus::{digest[:24]}"


def _add_chunks(
    engine,
    *,
    source_kind: str,
    source_ref: str,
    title: str,
    text: str,
    tags: list[str],
    domain: str,
    max_chars: int,
) -> tuple[int, int]:
    added = 0
    skipped = 0
    for idx, chunk in enumerate(_chunks(text, max_chars), start=1):
        rid = _record_id(source_kind, source_ref, idx, chunk)
        embed_text = CorpusMemory.make_embed_text(
            source_kind=source_kind,
            source_ref=source_ref,
            title=f"{title} [chunk {idx}]",
            text=chunk,
            tags=tags,
            domain=domain,
        )
        rec = CorpusMemory(
            record_id=rid,
            source_kind=source_kind,
            source_ref=source_ref,
            title=f"{title} [chunk {idx}]",
            text=chunk,
            tags=list(tags),
            domain=domain,
            embed_text=embed_text,
        )
        if engine.store_corpus(rec):
            added += 1
        else:
            skipped += 1
    return added, skipped


def _safe_run(args: list[str], timeout_s: int = 8) -> str:
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
    except Exception:
        return ""
    out = (proc.stdout or "").strip()
    if out:
        return out
    return (proc.stderr or "").strip()


def _ingest_help(engine, commands: Iterable[str], max_chars: int) -> dict[str, int]:
    added = 0
    skipped = 0
    sources = 0
    for cmd in commands:
        cmd = str(cmd or "").strip()
        if not cmd:
            continue
        help_text = _safe_run([cmd, "--help"], timeout_s=6)
        if not help_text:
            help_text = _safe_run([cmd, "-h"], timeout_s=6)
        if not help_text:
            continue
        a, s = _add_chunks(
            engine,
            source_kind="help",
            source_ref=cmd,
            title=f"{cmd} --help",
            text=help_text,
            tags=["help", cmd],
            domain="local_runtime",
            max_chars=max_chars,
        )
        added += a
        skipped += s
        sources += 1
    return {"sources": sources, "added": added, "skipped": skipped}


def _ingest_man(engine, commands: Iterable[str], max_chars: int) -> dict[str, int]:
    added = 0
    skipped = 0
    sources = 0
    for cmd in commands:
        cmd = str(cmd or "").strip()
        if not cmd:
            continue
        rendered = _safe_run(
            ["bash", "-lc", f"MANWIDTH=120 man {shlex.quote(cmd)} | col -b"],
            timeout_s=10,
        )
        if not rendered:
            continue
        a, s = _add_chunks(
            engine,
            source_kind="man",
            source_ref=cmd,
            title=f"man {cmd}",
            text=rendered,
            tags=["man", cmd],
            domain="local_runtime",
            max_chars=max_chars,
        )
        added += a
        skipped += s
        sources += 1
    return {"sources": sources, "added": added, "skipped": skipped}


def _summarize_pearl(line: str) -> str:
    try:
        pearl = json.loads(line)
    except Exception:
        return ""
    ts = str(pearl.get("timestamp", ""))
    energy = pearl.get("energy_snapshot", {}) or {}
    target = pearl.get("target_snapshot", {}) or {}
    identity = str(energy.get("identity_key") or target.get("identity_key") or "")
    domain = str(energy.get("domain") or target.get("domain") or "")
    reasons = pearl.get("reason_changes", []) or []
    states = pearl.get("state_changes", []) or []
    projections = pearl.get("projection_changes", []) or []
    refs = pearl.get("observation_refs", []) or []
    return (
        f"timestamp={ts}; identity={identity}; domain={domain}; "
        f"reasons={len(reasons)}; state_changes={len(states)}; "
        f"projection_changes={len(projections)}; observation_refs={len(refs)}"
    )


def _ingest_pearls(engine, pearls_path: Path, max_chars: int, max_records: int) -> dict[str, int]:
    if not pearls_path.exists():
        return {"sources": 0, "added": 0, "skipped": 0}

    lines = pearls_path.read_text(errors="replace").splitlines()
    if max_records > 0:
        lines = lines[-max_records:]

    added = 0
    skipped = 0
    for idx, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        summary = _summarize_pearl(line)
        if not summary:
            continue
        a, s = _add_chunks(
            engine,
            source_kind="pearl",
            source_ref=f"{pearls_path}:{idx}",
            title=f"pearl #{idx}",
            text=summary,
            tags=["pearl", "history"],
            domain="structural_memory",
            max_chars=max_chars,
        )
        added += a
        skipped += s
    return {"sources": len(lines), "added": added, "skipped": skipped}


def _iter_code_files(code_root: Path, max_files: int) -> Iterable[Path]:
    allowed = {".py", ".md", ".txt", ".yaml", ".yml", ".json", ".sh"}
    ignore_dirs = {
        ".git",
        ".venv",
        "node_modules",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
    }
    count = 0
    for path in code_root.rglob("*"):
        if count >= max_files:
            break
        if not path.is_file():
            continue
        if any(part in ignore_dirs for part in path.parts):
            continue
        if path.suffix.lower() not in allowed:
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size <= 0 or size > 600_000:
            continue
        yield path
        count += 1


def _ingest_code(engine, code_root: Path, max_files: int, max_chars: int) -> dict[str, int]:
    added = 0
    skipped = 0
    sources = 0

    for path in _iter_code_files(code_root, max_files=max_files):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        text = text.strip()
        if not text:
            continue
        # Bound per-file content to keep index compact.
        text = text[:8000]
        rel = str(path.relative_to(code_root))
        a, s = _add_chunks(
            engine,
            source_kind="code",
            source_ref=rel,
            title=rel,
            text=text,
            tags=["code", path.suffix.lower().lstrip(".")],
            domain="local_codebase",
            max_chars=max_chars,
        )
        added += a
        skipped += s
        sources += 1
    return {"sources": sources, "added": added, "skipped": skipped}


def _parse_csv(text: str | None) -> list[str]:
    if not text:
        return []
    out: list[str] = []
    for item in str(text).split(","):
        t = item.strip()
        if t:
            out.append(t)
    return out


def _dedupe_keep_order(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for raw in items:
        item = str(raw or "").strip()
        if not item or item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _query_tokens(text: str | None) -> set[str]:
    if not text:
        return set()
    return {
        tok.lower()
        for tok in re.findall(r"[a-zA-Z0-9_+.-]+", str(text))
        if len(tok) >= 2
    }


def discover_local_capabilities(
    *,
    help_candidates: Iterable[str] | None = None,
    man_candidates: Iterable[str] | None = None,
    code_root: str | None = None,
) -> dict[str, Any]:
    from skg_core.config.paths import SKG_HOME, SKG_STATE_DIR

    help_list = _dedupe_keep_order(help_candidates or DEFAULT_HELP_CANDIDATES)
    man_list = _dedupe_keep_order(man_candidates or DEFAULT_MAN_CANDIDATES)

    available_help = [cmd for cmd in help_list if shutil.which(cmd)]

    man_available: list[str] = []
    man_bin = shutil.which("man")
    col_bin = shutil.which("col")
    if man_bin and col_bin:
        man_available = [cmd for cmd in man_list if shutil.which(cmd) or cmd == "man"]

    root = Path(code_root).expanduser() if code_root else SKG_HOME
    pearls_path = SKG_STATE_DIR / "pearls.jsonl"

    return {
        "available_help_commands": available_help,
        "available_man_commands": man_available,
        "has_man_renderer": bool(man_bin and col_bin),
        "code_root": str(root),
        "code_root_exists": bool(root.exists() and root.is_dir()),
        "pearls_path": str(pearls_path),
        "pearls_exists": pearls_path.exists(),
        "cwd": os.getcwd(),
    }


def _sort_commands_for_query(commands: list[str], query_tokens: set[str]) -> list[str]:
    if not commands:
        return []

    def _rank(cmd: str) -> tuple[int, int, str]:
        lower = cmd.lower()
        return (0 if lower in query_tokens else 1, len(lower), lower)

    return sorted(commands, key=_rank)


def plan_smart_local_index(
    *,
    query: str | None = None,
    theta: str | None = None,
    code_root: str | None = None,
    help_candidates: Iterable[str] | None = None,
    man_candidates: Iterable[str] | None = None,
    max_help_cmds: int = 10,
    max_man_cmds: int = 8,
) -> dict[str, Any]:
    caps = discover_local_capabilities(
        help_candidates=help_candidates,
        man_candidates=man_candidates,
        code_root=code_root,
    )
    query_tokens = _query_tokens(query)
    query_tokens.update(_query_tokens(theta))

    help_pool = _sort_commands_for_query(
        list(caps.get("available_help_commands", []) or []),
        query_tokens=query_tokens,
    )
    man_pool = _sort_commands_for_query(
        list(caps.get("available_man_commands", []) or []),
        query_tokens=query_tokens,
    )

    max_help_cmds = max(0, int(max_help_cmds))
    max_man_cmds = max(0, int(max_man_cmds))

    return {
        "query_tokens": sorted(query_tokens),
        "help_cmds": help_pool[:max_help_cmds],
        "man_cmds": man_pool[:max_man_cmds],
        "capabilities": caps,
    }


def _default_smart_state_path() -> Path:
    from skg_core.config.paths import SKG_STATE_DIR

    return SKG_STATE_DIR / "resonance" / "local_corpus_smart_state.json"


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        os.replace(tmp, path)
    except Exception as exc:
        log.warning("[local_corpus] failed writing smart state %s: %s", path, exc)


def smart_index_local_corpus(
    engine,
    *,
    query: str | None = None,
    theta: str | None = None,
    force: bool = False,
    min_interval_s: int = 1800,
    state_path: str | None = None,
    include_pearls: bool = True,
    code_root: str | None = None,
    max_code_files: int = 160,
    chunk_chars: int = 900,
    max_pearl_records: int = 500,
    max_help_cmds: int = 10,
    max_man_cmds: int = 8,
) -> dict[str, Any]:
    now_ts = time.time()
    state_file = Path(state_path).expanduser() if state_path else _default_smart_state_path()
    previous = _read_json(state_file)
    last_run_ts = float(previous.get("last_run_ts", 0.0) or 0.0)
    min_interval_s = max(60, int(min_interval_s))
    due = force or (last_run_ts <= 0.0) or (now_ts - last_run_ts >= min_interval_s)

    plan = plan_smart_local_index(
        query=query,
        theta=theta,
        code_root=code_root,
        max_help_cmds=max_help_cmds,
        max_man_cmds=max_man_cmds,
    )
    help_cmds = list(plan.get("help_cmds", []) or [])
    man_cmds = list(plan.get("man_cmds", []) or [])

    base = {
        "query": str(query or ""),
        "theta": str(theta or ""),
        "force": bool(force),
        "due": bool(due),
        "min_interval_s": int(min_interval_s),
        "state_path": str(state_file),
        "last_run_ts": last_run_ts,
        "last_run_age_s": round(max(0.0, now_ts - last_run_ts), 3) if last_run_ts > 0 else None,
        "plan": {
            "help_cmds": help_cmds,
            "man_cmds": man_cmds,
            "query_tokens": plan.get("query_tokens", []),
        },
        "capabilities": plan.get("capabilities", {}),
    }
    if not due:
        base["skipped"] = True
        base["reason"] = "interval_not_elapsed"
        return base

    result = index_local_corpus(
        engine,
        pearls=include_pearls,
        help_cmds=",".join(help_cmds),
        man_cmds=",".join(man_cmds),
        code_root=code_root,
        max_code_files=max_code_files,
        chunk_chars=chunk_chars,
        max_pearl_records=max_pearl_records,
    )

    payload = {
        "version": 1,
        "last_run_ts": now_ts,
        "query": str(query or ""),
        "theta": str(theta or ""),
        "plan": base["plan"],
        "totals": result.get("totals", {}),
    }
    _write_json(state_file, payload)

    base["skipped"] = False
    base["result"] = result
    return base


_CODE_SUFFIXES = {".py", ".md", ".txt", ".yaml", ".yml", ".json", ".sh"}
_MICRO_PATH_RE = re.compile(r"[A-Za-z0-9_./~+-]+")


def _default_micro_state_path() -> Path:
    from skg_core.config.paths import SKG_STATE_DIR

    return SKG_STATE_DIR / "resonance" / "local_corpus_micro_state.json"


def _extract_file_hints(text: str | None) -> list[str]:
    if not text:
        return []
    out: list[str] = []
    for raw in _MICRO_PATH_RE.findall(str(text)):
        tok = raw.strip(".,:;()[]{}<>\"'")
        if not tok:
            continue
        if "/" in tok or tok.startswith(".") or tok.startswith("~"):
            out.append(tok)
            continue
        if "." in tok:
            suffix = "." + tok.rsplit(".", 1)[1].lower()
            if suffix in _CODE_SUFFIXES:
                out.append(tok)
    return _dedupe_keep_order(out)


def _resolve_micro_code_paths(code_root: Path, hints: list[str], max_files: int) -> list[Path]:
    if max_files <= 0:
        return []
    root = code_root.expanduser().resolve()
    selected: list[Path] = []
    for hint in hints:
        token = str(hint or "").strip()
        if not token:
            continue
        path_hint = Path(token).expanduser()
        candidates = [path_hint] if path_hint.is_absolute() else [root / path_hint, Path.cwd() / path_hint]
        for cand in candidates:
            try:
                resolved = cand.resolve()
            except Exception:
                continue
            if not resolved.exists() or not resolved.is_file():
                continue
            try:
                resolved.relative_to(root)
            except Exception:
                continue
            if resolved.suffix.lower() not in _CODE_SUFFIXES:
                continue
            if resolved in selected:
                continue
            selected.append(resolved)
            if len(selected) >= max_files:
                return selected
    return selected


def _source_ttl_split(
    selected: list[str],
    source_kind: str,
    *,
    source_state: dict[str, Any],
    now_ts: float,
    ttl_s: int,
    force: bool,
) -> tuple[list[str], list[str]]:
    due: list[str] = []
    ttl_skipped: list[str] = []
    for item in selected:
        source_key = f"{source_kind}:{item}"
        prev_ts = float(source_state.get(source_key, 0.0) or 0.0)
        is_due = force or prev_ts <= 0.0 or (now_ts - prev_ts) >= ttl_s
        if is_due:
            due.append(item)
        else:
            ttl_skipped.append(item)
    return due, ttl_skipped


def _command_match_rank(command: str, query_tokens: set[str]) -> tuple[int, int]:
    lower = command.lower()
    if lower in query_tokens:
        return (0, len(lower))
    base = lower.rstrip("0123456789")
    if base and base in query_tokens:
        return (1, len(lower))
    return (2, len(lower))


def _select_micro_commands(commands: list[str], query_tokens: set[str], max_items: int) -> list[str]:
    if max_items <= 0:
        return []
    matched = [cmd for cmd in commands if _command_match_rank(cmd, query_tokens)[0] < 2]
    ranked = sorted(matched, key=lambda cmd: _command_match_rank(cmd, query_tokens))
    return ranked[:max_items]


def _ingest_selected_code(
    engine,
    *,
    code_root: Path,
    paths: list[Path],
    max_chars: int,
) -> dict[str, int]:
    added = 0
    skipped = 0
    sources = 0
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8", errors="replace").strip()
        except Exception:
            continue
        if not text:
            continue
        text = text[:5000]
        try:
            source_ref = str(path.relative_to(code_root))
        except Exception:
            source_ref = str(path)
        a, s = _add_chunks(
            engine,
            source_kind="code",
            source_ref=source_ref,
            title=source_ref,
            text=text,
            tags=["code", path.suffix.lower().lstrip(".")],
            domain="local_codebase",
            max_chars=max_chars,
        )
        added += a
        skipped += s
        sources += 1
    return {"sources": sources, "added": added, "skipped": skipped}


def micro_index_local_corpus(
    engine,
    *,
    query: str | None = None,
    theta: str | None = None,
    force: bool = False,
    ttl_s: int = 900,
    state_path: str | None = None,
    code_root: str | None = None,
    max_help_cmds: int = 2,
    max_man_cmds: int = 2,
    max_code_files: int = 3,
    chunk_chars: int = 700,
    help_candidates: Iterable[str] | None = None,
    man_candidates: Iterable[str] | None = None,
) -> dict[str, Any]:
    ttl_s = max(30, min(int(ttl_s), 30 * 24 * 3600))
    chunk_chars = max(200, min(int(chunk_chars), 4000))
    max_help_cmds = max(0, min(int(max_help_cmds), 16))
    max_man_cmds = max(0, min(int(max_man_cmds), 16))
    max_code_files = max(0, min(int(max_code_files), 20))

    plan = plan_smart_local_index(
        query=query,
        theta=theta,
        code_root=code_root,
        help_candidates=help_candidates,
        man_candidates=man_candidates,
        max_help_cmds=max(1, max_help_cmds * 3) if max_help_cmds else 0,
        max_man_cmds=max(1, max_man_cmds * 3) if max_man_cmds else 0,
    )
    caps = dict(plan.get("capabilities", {}) or {})
    query_tokens = set(plan.get("query_tokens", []) or [])
    code_root_path = Path(caps.get("code_root") or (code_root or ".")).expanduser()

    selected_help = _select_micro_commands(
        list(caps.get("available_help_commands", []) or []),
        query_tokens=query_tokens,
        max_items=max_help_cmds,
    )
    selected_man = _select_micro_commands(
        list(caps.get("available_man_commands", []) or []),
        query_tokens=query_tokens,
        max_items=max_man_cmds,
    )
    file_hints = _extract_file_hints(query)
    selected_code_paths = _resolve_micro_code_paths(
        code_root_path,
        file_hints,
        max_files=max_code_files,
    )
    selected_code_refs = [
        str(path.relative_to(code_root_path.resolve()))
        if path.is_absolute()
        else str(path)
        for path in selected_code_paths
    ]

    selected_any = bool(selected_help or selected_man or selected_code_refs)
    state_file = Path(state_path).expanduser() if state_path else _default_micro_state_path()
    state = _read_json(state_file)
    source_state = dict(state.get("sources", {}) if isinstance(state.get("sources"), dict) else {})
    now_ts = time.time()

    due_help, skipped_help = _source_ttl_split(
        selected_help,
        "help",
        source_state=source_state,
        now_ts=now_ts,
        ttl_s=ttl_s,
        force=force,
    )
    due_man, skipped_man = _source_ttl_split(
        selected_man,
        "man",
        source_state=source_state,
        now_ts=now_ts,
        ttl_s=ttl_s,
        force=force,
    )
    due_code_paths: list[Path] = []
    skipped_code: list[str] = []
    for path in selected_code_paths:
        key = f"code:{path}"
        prev_ts = float(source_state.get(key, 0.0) or 0.0)
        is_due = force or prev_ts <= 0.0 or (now_ts - prev_ts) >= ttl_s
        if is_due:
            due_code_paths.append(path)
        else:
            skipped_code.append(str(path))

    summary = {
        "help": {"sources": 0, "added": 0, "skipped": 0},
        "man": {"sources": 0, "added": 0, "skipped": 0},
        "code": {"sources": 0, "added": 0, "skipped": 0},
    }
    if due_help:
        summary["help"] = _ingest_help(engine, due_help, max_chars=chunk_chars)
    if due_man:
        summary["man"] = _ingest_man(engine, due_man, max_chars=chunk_chars)
    if due_code_paths:
        summary["code"] = _ingest_selected_code(
            engine,
            code_root=code_root_path.resolve(),
            paths=due_code_paths,
            max_chars=chunk_chars,
        )

    for cmd in due_help:
        source_state[f"help:{cmd}"] = now_ts
    for cmd in due_man:
        source_state[f"man:{cmd}"] = now_ts
    for path in due_code_paths:
        source_state[f"code:{path}"] = now_ts

    _write_json(
        state_file,
        {
            "version": 1,
            "last_run_ts": now_ts,
            "sources": source_state,
        },
    )

    totals = {
        "sources": sum(v.get("sources", 0) for v in summary.values()),
        "added": sum(v.get("added", 0) for v in summary.values()),
        "skipped": sum(v.get("skipped", 0) for v in summary.values()),
    }
    skipped = totals["sources"] == 0
    if not selected_any:
        reason = "no_query_signals"
    elif skipped and (skipped_help or skipped_man or skipped_code):
        reason = "ttl_not_elapsed_for_selected_sources"
    elif skipped:
        reason = "no_due_sources"
    else:
        reason = ""

    return {
        "query": str(query or ""),
        "theta": str(theta or ""),
        "force": bool(force),
        "ttl_s": ttl_s,
        "state_path": str(state_file),
        "selected": {
            "help": selected_help,
            "man": selected_man,
            "code": selected_code_refs,
        },
        "due": {
            "help": due_help,
            "man": due_man,
            "code": [str(path) for path in due_code_paths],
        },
        "skipped_by_ttl": {
            "help": skipped_help,
            "man": skipped_man,
            "code": skipped_code,
        },
        "query_tokens": sorted(query_tokens),
        "summary": summary,
        "totals": totals,
        "skipped": skipped,
        "reason": reason,
    }


def index_local_corpus(
    engine,
    *,
    pearls: bool = True,
    help_cmds: str | None = None,
    man_cmds: str | None = None,
    code_root: str | None = None,
    max_code_files: int = 120,
    chunk_chars: int = 900,
    max_pearl_records: int = 500,
) -> dict:
    from skg_core.config.paths import SKG_HOME, SKG_STATE_DIR

    chunk_chars = max(200, min(int(chunk_chars), 4000))
    max_code_files = max(10, min(int(max_code_files), 5000))
    max_pearl_records = max(10, min(int(max_pearl_records), 50000))

    help_list = _parse_csv(help_cmds)
    man_list = _parse_csv(man_cmds)
    root = Path(code_root).expanduser() if code_root else SKG_HOME

    summary: dict[str, dict[str, int]] = {
        "pearls": {"sources": 0, "added": 0, "skipped": 0},
        "help": {"sources": 0, "added": 0, "skipped": 0},
        "man": {"sources": 0, "added": 0, "skipped": 0},
        "code": {"sources": 0, "added": 0, "skipped": 0},
    }

    if pearls:
        summary["pearls"] = _ingest_pearls(
            engine,
            pearls_path=SKG_STATE_DIR / "pearls.jsonl",
            max_chars=chunk_chars,
            max_records=max_pearl_records,
        )
    if help_list:
        summary["help"] = _ingest_help(engine, help_list, max_chars=chunk_chars)
    if man_list:
        summary["man"] = _ingest_man(engine, man_list, max_chars=chunk_chars)
    if root.exists() and root.is_dir():
        summary["code"] = _ingest_code(
            engine,
            code_root=root,
            max_files=max_code_files,
            max_chars=chunk_chars,
        )

    totals = {
        "sources": sum(v.get("sources", 0) for v in summary.values()),
        "added": sum(v.get("added", 0) for v in summary.values()),
        "skipped": sum(v.get("skipped", 0) for v in summary.values()),
    }
    return {
        "summary": summary,
        "totals": totals,
        "code_root": str(root),
        "help_cmds": help_list,
        "man_cmds": man_list,
        "pearls": bool(pearls),
        "max_code_files": max_code_files,
        "chunk_chars": chunk_chars,
    }
