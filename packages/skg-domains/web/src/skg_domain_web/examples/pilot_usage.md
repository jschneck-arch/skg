# Web Pilot Usage

Example adapter to projector flow:

1. Load findings from `skg_domain_web.fixtures.web_path_findings.json`.
2. Map findings to canonical events with `map_findings_to_events(...)`.
3. Project events with `compute_web(...)` or write an artifact with `project_events_to_artifact(...)`.

No `/opt/skg` assumptions are required by this pack.
