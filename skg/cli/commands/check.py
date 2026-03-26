from __future__ import annotations
import sys
from skg.cli.utils import SKG_STATE_DIR, SKG_CONFIG_DIR


def cmd_check(_a):
    """
    Startup validation: check that all required and optional components are
    available and correctly configured.  Prints a status table and exits
    non-zero if any critical component is missing.
    """
    import shutil, socket

    print("\n  SKG — startup check\n")
    ok_count = 0
    warn_count = 0
    fail_count = 0

    def row(label, status, detail=""):
        nonlocal ok_count, warn_count, fail_count
        if status == "ok":
            sym = "✓"; ok_count += 1
        elif status == "warn":
            sym = "⚠"; warn_count += 1
        else:
            sym = "✗"; fail_count += 1
        pad = " " * max(0, 30 - len(label))
        suffix = f"  ({detail})" if detail else ""
        print(f"    {sym}  {label}{pad}{suffix}")

    # ── Python version ──────────────────────────────────────────────────────
    import sys as _sys
    pv = _sys.version_info
    if pv >= (3, 11):
        row("Python", "ok", f"{pv.major}.{pv.minor}.{pv.micro}")
    else:
        row("Python", "fail", f"{pv.major}.{pv.minor} — need ≥ 3.11")

    # ── Core Python packages ────────────────────────────────────────────────
    for pkg, critical in [
        ("fastapi", True), ("uvicorn", True), ("pydantic", True),
        ("yaml", True), ("paramiko", True), ("requests", True),
        ("numpy", False), ("faiss", False),
        ("sentence_transformers", False), ("pywinrm", False),
        ("pymetasploit3", False),
    ]:
        try:
            __import__(pkg)
            row(f"pip: {pkg}", "ok")
        except ImportError:
            row(f"pip: {pkg}", "fail" if critical else "warn",
                "required" if critical else "optional")

    # ── System tools ────────────────────────────────────────────────────────
    print()
    for tool, critical, note in [
        ("nmap",        False, "needed for NSE CVE checks (HO-25)"),
        ("msfconsole",  False, "needed for exploit execution"),
        ("ollama",      False, "needed for local LLM / forge"),
        ("docker",      False, "needed for container toolchain"),
    ]:
        path = shutil.which(tool)
        if path:
            row(f"tool: {tool}", "ok", path)
        else:
            row(f"tool: {tool}", "warn", note)

    # ── State directory ─────────────────────────────────────────────────────
    print()
    import os as _os
    state = SKG_STATE_DIR
    if state.exists() and _os.access(state, _os.W_OK):
        row(f"state dir: {state}", "ok", "writable")
    elif state.exists():
        row(f"state dir: {state}", "fail", "exists but not writable")
    else:
        row(f"state dir: {state}", "warn", "will be created on first run")

    # ── Config files ────────────────────────────────────────────────────────
    for cf in [SKG_CONFIG_DIR / "targets.yaml",
               SKG_CONFIG_DIR / "skg_config.yaml"]:
        if cf.exists():
            row(f"config: {cf.name}", "ok")
        else:
            row(f"config: {cf.name}", "warn", f"not found at {cf}")

    # ── LLM backends ────────────────────────────────────────────────────────
    print()
    # Ollama
    try:
        import urllib.request as _ur
        _ur.urlopen("http://localhost:11434/api/tags", timeout=2).read()
        row("LLM: Ollama (localhost:11434)", "ok", "reachable")
    except Exception:
        row("LLM: Ollama (localhost:11434)", "warn", "not reachable — forge needs this or ANTHROPIC_API_KEY")

    # Anthropic API key
    if _os.environ.get("ANTHROPIC_API_KEY"):
        row("LLM: ANTHROPIC_API_KEY", "ok", "set")
    else:
        # Check skg.env
        env_file = SKG_CONFIG_DIR / "skg.env"
        if env_file.exists() and "ANTHROPIC_API_KEY" in env_file.read_text():
            row("LLM: ANTHROPIC_API_KEY", "ok", "found in skg.env")
        else:
            row("LLM: ANTHROPIC_API_KEY", "warn", "not set — optional but enables Claude backend")

    # ── Daemon ──────────────────────────────────────────────────────────────
    print()
    try:
        s = socket.create_connection(("127.0.0.1", 5055), timeout=1)
        s.close()
        row("daemon: port 5055", "ok", "reachable")
    except Exception:
        row("daemon: port 5055", "warn", "not running — start with: skg start")

    # ── Summary ─────────────────────────────────────────────────────────────
    print()
    print(f"  Summary: {ok_count} ok, {warn_count} warn, {fail_count} fail")
    if fail_count:
        print(f"  Action required: fix {fail_count} critical issue(s) before running")
        raise SystemExit(1)
    elif warn_count:
        print(f"  Optional components missing — core engagement loop will work")
    else:
        print(f"  All systems nominal — ready to engage")
    print()
