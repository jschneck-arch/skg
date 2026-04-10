from __future__ import annotations

import argparse

from skg_core.config.paths import SKG_STATE_DIR

from skg.cli.commands.check import cmd_check
from skg.cli.commands.core import cmd_core
from skg.cli.commands.data import cmd_data
from skg.cli.commands.derived import cmd_derived
from skg.cli.commands.exploit import cmd_audit, cmd_collect, cmd_exploit
from skg.cli.commands.gravity import cmd_gravity
from skg.cli.commands.intelligence import cmd_feed, cmd_graph, cmd_resonance
from skg.cli.commands.proposals import cmd_proposals
from skg.cli.commands.report import cmd_calibrate, cmd_engage, cmd_report
from skg.cli.commands.replay import cmd_replay
from skg.cli.commands.surface import cmd_field, cmd_folds, cmd_surface, cmd_web_view
from skg.cli.commands.system import cmd_identity, cmd_mode, cmd_start, cmd_status, cmd_stop
from skg.cli.commands.target import cmd_observe, cmd_target
from skg.cli.commands.toolchains import cmd_aprs, cmd_catalog, cmd_escape, cmd_lateral


CLI_DESCRIPTION = "SKG — Spherical Knowledge Graph"


COMMAND_DISPATCH = {
    "aprs": cmd_aprs,
    "audit": cmd_audit,
    "calibrate": cmd_calibrate,
    "catalog": cmd_catalog,
    "check": cmd_check,
    "core": cmd_core,
    "collect": cmd_collect,
    "data": cmd_data,
    "derived": cmd_derived,
    "engage": cmd_engage,
    "escape": cmd_escape,
    "exploit": cmd_exploit,
    "feed": cmd_feed,
    "field": cmd_field,
    "folds": cmd_folds,
    "graph": cmd_graph,
    "gravity": cmd_gravity,
    "identity": cmd_identity,
    "lateral": cmd_lateral,
    "mode": cmd_mode,
    "observe": cmd_observe,
    "proposals": cmd_proposals,
    "replay": cmd_replay,
    "report": cmd_report,
    "resonance": cmd_resonance,
    "start": cmd_start,
    "status": cmd_status,
    "stop": cmd_stop,
    "surface": cmd_surface,
    "target": cmd_target,
    "web": cmd_web_view,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="skg", description=CLI_DESCRIPTION)
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("start", help="start the gravity field")
    sub.add_parser("stop", help="stop the gravity field")

    status_parser = sub.add_parser("status", help="entropy landscape + field state")
    status_parser.add_argument(
        "--self-audit",
        action="store_true",
        help="audit SKG substrate health: memory, folds, proposals, recall, feedback, local model",
    )
    sub.add_parser("surface", help="full attack surface map")
    sub.add_parser("web", help="gravity web — bonds + coupling")

    target_parser = sub.add_parser("target", help="topology management")
    target_sub = target_parser.add_subparsers(dest="target_cmd", required=True)

    target_add = target_sub.add_parser("add", help="add mass to the field")
    target_add.add_argument("ip")
    target_add.add_argument("--domain", default=None)

    target_add_subnet = target_sub.add_parser("add-subnet", help="discover subnet, add targets")
    target_add_subnet.add_argument("cidr")
    target_add_subnet.add_argument("--deep", action="store_true")

    target_remove = target_sub.add_parser("remove", help="remove mass from the field")
    target_remove.add_argument("ip")

    target_sub.add_parser("list", help="all targets with entropy")

    target_link = target_sub.add_parser("link", help="assert a bond")
    target_link.add_argument("ip1")
    target_link.add_argument("ip2")
    target_link.add_argument("bond_type")

    target_sub.add_parser("edges", help="all bonds in the gravity web")

    sub.add_parser("check", help="validate required tools and configuration")

    core_parser = sub.add_parser("core", help="core runtime helpers and configuration")
    core_sub = core_parser.add_subparsers(dest="core_cmd", required=True)
    core_coupling = core_sub.add_parser("coupling", help="show, learn, validate, and apply coupling config")
    coupling_action = core_coupling.add_mutually_exclusive_group()
    coupling_action.add_argument("--validate", action="store_true", help="validate the active coupling config")
    coupling_action.add_argument("--show", action="store_true", help="print the active merged coupling config")
    coupling_action.add_argument("--learn", action="store_true", help="estimate intra-target couplings from delta snapshots")
    coupling_action.add_argument("--apply", action="store_true", help="apply learned intra-target couplings to the live config")
    core_coupling.add_argument("--delta-dir", default=str(SKG_STATE_DIR / "delta"), help="delta directory for --learn/--apply")
    core_coupling.add_argument("--out", default=None, help="write --learn output to a file instead of stdout")
    core_coupling.add_argument("--learned-file", default=None, help="use a learned coupling file for --apply")
    core_coupling.add_argument("--review", action="store_true", help="show a unified diff before --apply")
    core_coupling.add_argument("--backup", action="store_true", help="back up the active coupling file before --apply")
    core_coupling.add_argument("--yes", action="store_true", help="skip interactive confirmation during --apply")

    replay_parser = sub.add_parser("replay", help="replay recorded events and show field state")
    replay_parser.add_argument("events_dir", help="directory containing .ndjson event files")

    observe_parser = sub.add_parser("observe", help="trigger observation on a target")
    observe_parser.add_argument("ip")
    observe_parser.add_argument(
        "--with",
        dest="instrument",
        default=None,
        choices=["web", "ssh", "nmap", "msf", "pcap"],
    )
    observe_parser.add_argument(
        "--auth",
        action="store_true",
        help="authenticated scan (for --with web)",
    )

    proposals_parser = sub.add_parser("proposals", help="operator proposal queue")
    proposals_sub = proposals_parser.add_subparsers(dest="proposal_cmd", required=True)
    proposals_list = proposals_sub.add_parser("list", help="list proposals")
    proposals_list.add_argument("--status", default="all")
    proposals_sub.add_parser("show", help="show proposal").add_argument("proposal_id")
    proposals_trigger = proposals_sub.add_parser("trigger", help="trigger field_action proposal")
    proposals_trigger.add_argument("proposal_id")
    proposals_trigger.add_argument(
        "--await-session",
        action="store_true",
        help="detect open MSF session and run post-exploitation collection",
    )
    proposals_sub.add_parser("accept", help="accept toolchain proposal").add_argument("proposal_id")
    proposals_reject = proposals_sub.add_parser("reject", help="reject proposal")
    proposals_reject.add_argument("proposal_id")
    proposals_reject.add_argument("--reason", default="")
    proposals_defer = proposals_sub.add_parser("defer", help="defer proposal")
    proposals_defer.add_argument("proposal_id")
    proposals_defer.add_argument("days", nargs="?", type=int, default=7)

    data_parser = sub.add_parser("data", help="data pipeline integrity — DP-01..DP-15 wickets")
    data_sub = data_parser.add_subparsers(dest="data_cmd", required=False)
    data_profile = data_sub.add_parser("profile", help="profile a database table against a contract")
    data_profile.add_argument("--url", required=True, help="SQLAlchemy DB URL")
    data_profile.add_argument("--table", required=True, help="table or view to profile")
    data_profile.add_argument("--workload-id", dest="workload_id", default=None)
    data_profile.add_argument("--contract", default=None, help="schema contract JSON")
    data_profile.add_argument(
        "--attack-path-id",
        dest="attack_path_id",
        default="data_completeness_failure_v1",
    )
    data_profile.add_argument("--out", default=None)
    data_project = data_sub.add_parser("project", help="project DP-* events against a failure path")
    data_project.add_argument("--in", dest="infile", required=True)
    data_project.add_argument("--path-id", dest="path_id", required=True)
    data_sub.add_parser("paths", help="list all data failure paths")
    data_sub.add_parser("catalog", help="print the full data catalog JSON")
    data_discover = data_sub.add_parser(
        "discover",
        help="SSH-discover DB services and run combined DE-* + DP-* assessment",
    )
    data_discover.add_argument("--host", required=True, help="target IP or hostname")
    data_discover.add_argument("--user", required=True, help="SSH username")
    data_discover.add_argument("--password", default=None, help="SSH password")
    data_discover.add_argument("--key", default=None, help="SSH key file")
    data_discover.add_argument("--ssh-port", dest="ssh_port", type=int, default=22)
    data_discover.add_argument("--workload-id", dest="workload_id", default=None)
    data_discover.add_argument("--tables", default=None, help="comma-separated subset of tables to profile")
    data_discover.add_argument("--out-dir", dest="out_dir", default=None)

    collect_parser = sub.add_parser("collect", help="collect from a specific host")
    collect_parser.add_argument("--target", required=True, help="target IP or hostname")
    collect_parser.add_argument("--method", default="ssh", choices=["ssh", "winrm"])
    collect_parser.add_argument("--user", default=None)
    collect_parser.add_argument("--key", default=None)
    collect_parser.add_argument("--port", type=int, default=22)
    collect_parser.add_argument("--auto-project", dest="auto_project", action="store_true")

    gravity_parser = sub.add_parser("gravity", help="run the gravity field loop")
    gravity_parser.add_argument("--cycles", type=int, default=5)
    gravity_parser.add_argument("--target", default=None)
    gravity_parser.add_argument(
        "--authorized",
        action="store_true",
        help="Authorized engagement: auto-execute exploit proposals without operator trigger",
    )

    derived_parser = sub.add_parser("derived", help="archive or rebuild derived operator state")
    derived_sub = derived_parser.add_subparsers(dest="derived_cmd", required=True)
    derived_sub.add_parser("archive", help="archive derived interp/fold state and recreate empty directories")
    derived_rebuild = derived_sub.add_parser(
        "rebuild",
        help="rebuild derived interp/fold state from events and discovery artifacts",
    )
    derived_rebuild.add_argument(
        "--append",
        action="store_true",
        help="append rebuild output into existing derived directories",
    )

    report_parser = sub.add_parser("report", help="substrate report from canonical state")
    report_parser.add_argument("--target", default=None, help="scope report to one target in surface")
    report_parser.add_argument("--at", default=None, help="show target state as of an ISO timestamp from pearls")
    report_parser.add_argument(
        "--diff-against",
        dest="diff_against",
        default=None,
        help="diff current target state against an ISO timestamp from pearls",
    )
    report_parser.add_argument("--json", dest="json_out", action="store_true", help="emit raw JSON report")
    report_parser.add_argument("--llm", action="store_true", help="ask TinyLlama for a short narrative summary")

    mode_parser = sub.add_parser("mode", help="set operational mode")
    mode_parser.add_argument(
        "set_mode",
        nargs="?",
        choices=["kernel", "resonance", "unified", "anchor"],
    )
    mode_parser.add_argument("--reason", default="")

    calibrate_parser = sub.add_parser(
        "calibrate",
        help="learn per-sensor confidence weights from engagement history",
    )
    calibrate_parser.add_argument(
        "--db",
        default=str(SKG_STATE_DIR / "engagement.db"),
        help="engagement database (build with: skg engage build)",
    )
    calibrate_parser.add_argument("--report", action="store_true", help="print calibration report without saving")

    engage_parser = sub.add_parser(
        "engage",
        help="engagement dataset — build DB from telemetry + analyze integrity",
    )
    engage_sub = engage_parser.add_subparsers(dest="engage_cmd", required=False)
    engage_build = engage_sub.add_parser("build", help="build SQLite DB from all telemetry")
    engage_build.add_argument("--out", default=str(SKG_STATE_DIR / "engagement.db"))
    engage_analyze = engage_sub.add_parser("analyze", help="analyze dataset integrity (DP-* checks)")
    engage_analyze.add_argument("--db", default=str(SKG_STATE_DIR / "engagement.db"))
    engage_report = engage_sub.add_parser("report", help="full engagement report")
    engage_report.add_argument("--db", default=str(SKG_STATE_DIR / "engagement.db"))
    engage_report.add_argument("--out", default=None, help="write JSON report to file")
    engage_clean = engage_sub.add_parser(
        "clean",
        help="repair DP-03/04/05 violations (null fields, out-of-bounds values, orphans)",
    )
    engage_clean.add_argument("--db", default=str(SKG_STATE_DIR / "engagement.db"))

    audit_parser = sub.add_parser("audit", help="system integrity — FI/PI/LI wickets")
    audit_sub = audit_parser.add_subparsers(dest="audit_cmd", required=False)
    audit_scan = audit_sub.add_parser("scan", help="audit a host via SSH")
    audit_scan.add_argument("--target", required=True)
    audit_scan.add_argument("--user", default=None)
    audit_scan.add_argument("--key", default=None)
    audit_scan.add_argument("--password", default=None)
    audit_scan.add_argument("--workload-id", dest="workload_id", default=None)
    audit_scan.add_argument(
        "--attack-path-id",
        dest="attack_path_id",
        default="full_system_integrity_v1",
    )
    audit_scan.add_argument("--checks", default=None, help="comma-separated check IDs e.g. fi01,pi02,li05")
    audit_project = audit_sub.add_parser("project", help="project FI/PI/LI events against a path")
    audit_project.add_argument("--in", dest="infile", required=True)
    audit_project.add_argument("--path-id", dest="path_id", required=True)
    audit_sub.add_parser("paths", help="list system integrity failure paths")

    exploit_parser = sub.add_parser(
        "exploit",
        help="translate realized paths into MSF proposals + binary analysis",
    )
    exploit_sub = exploit_parser.add_subparsers(dest="exploit_cmd", required=False)
    exploit_propose = exploit_sub.add_parser("propose", help="generate exploit proposals for a realized path")
    exploit_propose.add_argument("--path-id", required=True, help="attack path ID (e.g. web_sqli_to_shell_v1)")
    exploit_propose.add_argument("--target", required=True, help="target IP")
    exploit_propose.add_argument("--port", type=int, default=80)
    exploit_propose.add_argument("--realized", nargs="+", default=[], help="realized wicket IDs")
    exploit_propose.add_argument("--lhost", default="", help="local host IP for reverse shells")
    exploit_propose.add_argument("--session-id", dest="session_id", default="")
    exploit_privesc = exploit_sub.add_parser("privesc", help="post-session privesc chain proposals")
    exploit_privesc.add_argument("--session-id", dest="session_id", required=True)
    exploit_privesc.add_argument("--target", required=True)
    exploit_privesc.add_argument("--known", nargs="+", default=[], help="already-known wicket IDs")
    exploit_binary = exploit_sub.add_parser(
        "binary",
        help="analyze binary for BA-* wickets (NX, canary, overflow path)",
    )
    exploit_binary.add_argument("binary_path")
    exploit_binary.add_argument("--target", default="", help="SSH target host for remote analysis")
    exploit_binary.add_argument("--user", default="", help="SSH username for remote analysis")
    exploit_binary.add_argument("--password", default="", help="SSH password for remote analysis")
    exploit_binary.add_argument("--key", default="", help="SSH private key for remote analysis")
    exploit_binary.add_argument("--port", type=int, default=22, help="SSH port for remote analysis")
    exploit_binary.add_argument(
        "--attack-path-id",
        dest="attack_path_id",
        default="binary_stack_overflow_v1",
        help="binary attack path to project",
    )
    exploit_binary.add_argument("--workload-id", dest="workload_id", default="")
    exploit_sub.add_parser("list-paths", help="list all mapped exploit paths")
    exploit_sub.add_parser("binary-catalog", help="print binary analysis catalog JSON")
    exploit_cred_reuse = exploit_sub.add_parser(
        "cred-reuse",
        help="test stored credentials against a target's services",
    )
    exploit_cred_reuse.add_argument("--target", required=True, help="target IP or hostname")
    exploit_cred_reuse.add_argument(
        "--authorized",
        action="store_true",
        help="Test credentials directly (authorized engagement; default: generate proposals)",
    )

    graph_parser = sub.add_parser(
        "graph",
        help="wicket knowledge graph — Kuramoto K-topology, entanglement, phase gradient",
    )
    graph_parser.set_defaults(graph_cmd="topology")
    graph_sub = graph_parser.add_subparsers(dest="graph_cmd", required=False)
    graph_sub.add_parser("topology", help="global R, cluster R, entangled pairs, top gradient signals")
    graph_edges = graph_sub.add_parser("edges", help="neighbors, K values, and phase for a wicket")
    graph_edges.add_argument("wicket_id", help="e.g. HO-04")
    graph_sub.add_parser("entangled", help="all non-separable pairs (K ≥ 0.80)")
    graph_sub.add_parser("hypotheses", help="predicted wickets: observable vs dark (no instrument)")

    folds_parser = sub.add_parser("folds", help="structural knowledge gaps that add to field energy")
    folds_parser.set_defaults(folds_cmd="list")
    folds_sub = folds_parser.add_subparsers(dest="folds_cmd", required=False)
    folds_sub.add_parser("list", help="all active folds")
    folds_sub.add_parser("structural", help="services with no toolchain (dark attack surface)")
    folds_resolve = folds_sub.add_parser("resolve", help="mark fold as resolved after toolchain/mapping created")
    folds_resolve.add_argument("fold_id")
    folds_resolve.add_argument("--target", required=True, help="target IP")

    feed_parser = sub.add_parser("feed", help="intelligence feeds")
    feed_sub = feed_parser.add_subparsers(dest="feed_cmd", required=True)
    feed_nvd = feed_sub.add_parser("nvd", help="NVD CVE lookup")
    feed_nvd.add_argument("--service", default=None, help="specific service to look up")

    resonance_parser = sub.add_parser("resonance", help="semantic memory + catalog expansion")
    resonance_sub = resonance_parser.add_subparsers(dest="resonance_cmd", required=True)
    resonance_sub.add_parser("status")
    resonance_sub.add_parser("ingest")
    resonance_sub.add_parser("ollama")
    resonance_query = resonance_sub.add_parser("query")
    resonance_query.add_argument("text")
    resonance_query.add_argument(
        "--type",
        default="all",
        choices=["all", "wickets", "adapters", "domains", "corpus"],
    )
    resonance_query.add_argument("--k", type=int, default=5)
    resonance_draft = resonance_sub.add_parser("draft")
    resonance_draft.add_argument("domain")
    resonance_draft.add_argument("description")
    resonance_draft.add_argument("--api-key", dest="api_key", default=None)
    resonance_ask = resonance_sub.add_parser(
        "ask",
        help="layered local assistant (router + resonance memory + tiered Ollama models)",
    )
    resonance_ask.add_argument("text", help="request text")
    resonance_ask.add_argument(
        "--prefer",
        default=None,
        choices=["fast", "code", "deep"],
        help="force routing tier (default: automatic)",
    )
    resonance_ask.add_argument(
        "--k",
        type=int,
        default=None,
        help="retrieval depth per memory type (default from config)",
    )
    resonance_ask.add_argument(
        "--show-context",
        action="store_true",
        help="print retrieved resonance context snippets",
    )
    resonance_ask.add_argument(
        "--json",
        dest="json_out",
        action="store_true",
        help="emit full orchestration result as JSON",
    )
    resonance_sphere_status = resonance_sub.add_parser(
        "sphere-status",
        help="show SphereGPU virtual accelerator status and limits",
    )
    resonance_sphere_status.add_argument(
        "--json",
        dest="json_out",
        action="store_true",
        help="emit status as JSON",
    )
    resonance_sphere_ask = resonance_sub.add_parser(
        "sphere-ask",
        help="run one inference through SphereGPU spherical scheduler",
    )
    resonance_sphere_ask.add_argument("text", help="request text")
    resonance_sphere_ask.add_argument("--r", type=float, default=0.35, help="radial compute depth [0..1]")
    resonance_sphere_ask.add_argument("--theta", default="general", help="task family angle label")
    resonance_sphere_ask.add_argument("--phi", type=float, default=0.5, help="uncertainty / confidence [0..1]")
    resonance_sphere_ask.add_argument("--stream", type=int, default=0, help="virtual stream id")
    resonance_sphere_ask.add_argument(
        "--k",
        type=int,
        default=None,
        help="retrieval depth per memory type (default from sphere config)",
    )
    resonance_sphere_ask.add_argument(
        "--show-context",
        action="store_true",
        help="print retrieved resonance context snippets",
    )
    resonance_sphere_ask.add_argument(
        "--json",
        dest="json_out",
        action="store_true",
        help="emit full result as JSON",
    )
    resonance_sphere_batch = resonance_sub.add_parser(
        "sphere-batch",
        help="run a JSON/JSONL batch through SphereGPU in threaded lanes",
    )
    resonance_sphere_batch.add_argument(
        "--in",
        dest="infile",
        required=True,
        help="input JSON array or JSONL file with query/r/theta/phi/stream",
    )
    resonance_sphere_batch.add_argument(
        "--max-workers",
        type=int,
        default=None,
        help="override worker count (default: virtual cores)",
    )
    resonance_sphere_batch.add_argument(
        "--json",
        dest="json_out",
        action="store_true",
        help="emit full batch results as JSON",
    )
    resonance_index = resonance_sub.add_parser(
        "index-local",
        help="index local pearls/help/man/code into resonance corpus memory",
    )
    resonance_index.add_argument(
        "--no-pearls",
        action="store_true",
        help="skip pearls ingestion",
    )
    resonance_index.add_argument(
        "--help-cmds",
        default="",
        help="comma-separated commands to ingest from --help (e.g. ssh,nmap,rg)",
    )
    resonance_index.add_argument(
        "--man-cmds",
        default="",
        help="comma-separated commands to ingest man pages (e.g. ssh,find,bash)",
    )
    resonance_index.add_argument(
        "--code-root",
        default=None,
        help="root directory to index source/docs from (default: SKG repo root)",
    )
    resonance_index.add_argument(
        "--max-code-files",
        type=int,
        default=120,
        help="maximum number of files to index from code-root",
    )
    resonance_index.add_argument(
        "--chunk-chars",
        type=int,
        default=900,
        help="chunk size for indexed text blocks",
    )
    resonance_index.add_argument(
        "--max-pearl-records",
        type=int,
        default=500,
        help="maximum recent pearls to ingest",
    )
    resonance_caps = resonance_sub.add_parser(
        "capabilities",
        help="scan local runtime capabilities for smart resonance indexing",
    )
    resonance_caps.add_argument(
        "--json",
        dest="json_out",
        action="store_true",
        help="emit capability scan as JSON",
    )
    resonance_index_smart = resonance_sub.add_parser(
        "index-smart",
        help="auto-select local help/man/code sources and index them into corpus memory",
    )
    resonance_index_smart.add_argument(
        "--query",
        default="",
        help="optional query to prioritize command and source selection",
    )
    resonance_index_smart.add_argument(
        "--theta",
        default="general",
        help="task family hint used for source prioritization",
    )
    resonance_index_smart.add_argument(
        "--force",
        action="store_true",
        help="run immediately even if the index interval has not elapsed",
    )
    resonance_index_smart.add_argument(
        "--json",
        dest="json_out",
        action="store_true",
        help="emit full smart-index result as JSON",
    )
    resonance_index_micro = resonance_sub.add_parser(
        "index-micro",
        help="index only query-matched local commands/files with tiny budget",
    )
    resonance_index_micro.add_argument(
        "--query",
        default="",
        help="query text used to detect commands/files for micro indexing",
    )
    resonance_index_micro.add_argument(
        "--theta",
        default="general",
        help="task family hint",
    )
    resonance_index_micro.add_argument(
        "--force",
        action="store_true",
        help="ignore TTL and refresh selected sources now",
    )
    resonance_index_micro.add_argument(
        "--json",
        dest="json_out",
        action="store_true",
        help="emit full micro-index result as JSON",
    )
    resonance_mcp_status = resonance_sub.add_parser(
        "mcp-status",
        help="show layered MCP threading status",
    )
    resonance_mcp_status.add_argument(
        "--json",
        dest="json_out",
        action="store_true",
        help="emit status as JSON",
    )
    resonance_mcp_thread = resonance_sub.add_parser(
        "mcp-thread",
        help="run one layered MCP threaded query using SKG as source-of-truth",
    )
    resonance_mcp_thread.add_argument("text", help="request text")
    resonance_mcp_thread.add_argument(
        "--theta",
        default="general",
        help="task family angle label",
    )
    resonance_mcp_thread.add_argument(
        "--prefer",
        default=None,
        choices=["fast", "code", "deep"],
        help="force routing tier for reasoner layer",
    )
    resonance_mcp_thread.add_argument(
        "--k",
        type=int,
        default=None,
        help="retrieval depth per memory type",
    )
    resonance_mcp_thread.add_argument(
        "--max-workers",
        type=int,
        default=None,
        help="override layered thread pool worker count",
    )
    resonance_mcp_thread.add_argument(
        "--json",
        dest="json_out",
        action="store_true",
        help="emit full layered thread result as JSON",
    )
    resonance_sub.add_parser("drafts")
    resonance_dp = resonance_sub.add_parser(
        "draft-prompt",
        help="build a grounded prompt file (no API key needed) for manual use with claude.ai",
    )
    resonance_dp.add_argument("domain")
    resonance_dp.add_argument("description")
    resonance_da = resonance_sub.add_parser(
        "draft-accept",
        help="accept a JSON catalog response and save it as a draft",
    )
    resonance_da.add_argument("domain")
    resonance_da.add_argument(
        "response",
        help="path to a JSON file or inline JSON string with the catalog response",
    )

    identity_parser = sub.add_parser("identity", help="who is SKG")
    identity_parser.add_argument("subcommand", nargs="?", choices=["history"])

    field_parser = sub.add_parser("field", help="per-workload field state")
    field_parser.add_argument("workload_id")
    field_parser.add_argument(
        "domain",
        nargs="?",
        default="host",
        choices=[
            "host", "container_escape", "ad_lateral", "aprs",
            "web", "nginx", "binary", "binary_analysis", "supply_chain",
            "data", "data_pipeline", "ai_target", "iot_firmware", "metacognition",
        ],
    )

    catalog_parser = sub.add_parser("catalog", help="catalog management")
    catalog_sub = catalog_parser.add_subparsers(dest="catalog_cmd", required=True)
    catalog_compile = catalog_sub.add_parser("compile")
    catalog_compile.add_argument("--domain", required=True)
    catalog_compile.add_argument("--description", required=True)
    catalog_compile.add_argument("--packages", default="")
    catalog_compile.add_argument("--keywords", default="")
    catalog_compile.add_argument("--prefix", default=None)
    catalog_compile.add_argument("--api-key", default=None)
    catalog_compile.add_argument("--min-cvss", type=float, default=6.0)
    catalog_compile.add_argument("--max-wickets", type=int, default=20)
    catalog_compile.add_argument("--out", default=None)
    catalog_compile.add_argument("--dry-run", action="store_true")

    aprs_parser = sub.add_parser("aprs")
    aprs_sub = aprs_parser.add_subparsers(dest="aprs_cmd", required=True)
    aprs_sub.add_parser("paths")
    aprs_ingest = aprs_sub.add_parser("ingest")
    aprs_ingest.add_argument("adapter", choices=["config_effective", "net_sandbox"])
    aprs_ingest.add_argument("--out", required=True)
    aprs_ingest.add_argument("--attack-path-id", default="log4j_jndi_rce_v1")
    aprs_ingest.add_argument("--run-id", default=None)
    aprs_ingest.add_argument("--workload-id", default=None)
    aprs_ingest.add_argument("--root", default=None)
    aprs_ingest.add_argument("--docker-inspect", dest="docker_inspect", default=None)
    aprs_ingest.add_argument("--resolv-conf", dest="resolv_conf", default=None)
    aprs_ingest.add_argument("--iptables", default=None)
    aprs_ingest.add_argument("--ps", default=None)
    aprs_project = aprs_sub.add_parser("project")
    aprs_project.add_argument("--in", dest="infile", required=True)
    aprs_project.add_argument("--out", dest="outfile", required=True)
    aprs_project.add_argument("--attack-path-id", default="log4j_jndi_rce_v1")
    aprs_latest = aprs_sub.add_parser("latest")
    aprs_latest.add_argument("--interp", required=True)
    aprs_latest.add_argument("--attack-path-id", required=True)
    aprs_latest.add_argument("--workload-id", default=None)

    escape_parser = sub.add_parser("escape")
    escape_sub = escape_parser.add_subparsers(dest="escape_cmd", required=True)
    escape_sub.add_parser("paths")
    escape_ingest = escape_sub.add_parser("ingest")
    escape_ingest.add_argument("--inspect", required=True)
    escape_ingest.add_argument("--out", required=True)
    escape_ingest.add_argument("--attack-path-id", default="container_escape_privileged_v1")
    escape_ingest.add_argument("--run-id", default=None)
    escape_ingest.add_argument("--workload-id", default=None)
    escape_project = escape_sub.add_parser("project")
    escape_project.add_argument("--in", dest="infile", required=True)
    escape_project.add_argument("--out", dest="outfile", required=True)
    escape_project.add_argument("--attack-path-id", default="container_escape_privileged_v1")
    escape_latest = escape_sub.add_parser("latest")
    escape_latest.add_argument("--interp", required=True)
    escape_latest.add_argument("--attack-path-id", required=True)
    escape_latest.add_argument("--workload-id", default=None)

    lateral_parser = sub.add_parser("lateral")
    lateral_sub = lateral_parser.add_subparsers(dest="lateral_cmd", required=True)
    lateral_sub.add_parser("paths")
    lateral_ingest = lateral_sub.add_parser("ingest")
    lateral_ingest_sub = lateral_ingest.add_subparsers(dest="lateral_adapter", required=True)
    lateral_bloodhound = lateral_ingest_sub.add_parser("bloodhound")
    lateral_bloodhound.add_argument("--bh-dir", required=True, dest="bh_dir")
    lateral_bloodhound.add_argument("--out", required=True)
    lateral_bloodhound.add_argument("--attack-path-id", default="ad_kerberoast_v1")
    lateral_bloodhound.add_argument("--run-id", default=None)
    lateral_bloodhound.add_argument("--workload-id", default=None)
    lateral_ldap = lateral_ingest_sub.add_parser("ldapdomaindump")
    lateral_ldap.add_argument("--dump-dir", required=True, dest="dump_dir")
    lateral_ldap.add_argument("--out", required=True)
    lateral_ldap.add_argument("--attack-path-id", default="ad_kerberoast_v1")
    lateral_ldap.add_argument("--run-id", default=None)
    lateral_ldap.add_argument("--workload-id", default=None)
    lateral_manual = lateral_ingest_sub.add_parser("manual")
    lateral_manual.add_argument("--input", required=True)
    lateral_manual.add_argument("--out", required=True)
    lateral_manual.add_argument("--attack-path-id", default="ad_kerberoast_v1")
    lateral_manual.add_argument("--run-id", default=None)
    lateral_manual.add_argument("--workload-id", default=None)
    lateral_project = lateral_sub.add_parser("project")
    lateral_project.add_argument("--in", dest="infile", required=True)
    lateral_project.add_argument("--out", dest="outfile", required=True)
    lateral_project.add_argument("--attack-path-id", required=True)
    lateral_latest = lateral_sub.add_parser("latest")
    lateral_latest.add_argument("--interp", required=True)
    lateral_latest.add_argument("--attack-path-id", required=True)
    lateral_latest.add_argument("--workload-id", default=None)

    return parser


def dispatch_command(args: argparse.Namespace, parser: argparse.ArgumentParser | None = None):
    handler = COMMAND_DISPATCH.get(getattr(args, "command", None))
    if handler is None:
        (parser or build_parser()).print_help()
        return 0
    return handler(args)


def main(argv: list[str] | None = None):
    parser = build_parser()
    args = parser.parse_args(argv)
    return dispatch_command(args, parser)
