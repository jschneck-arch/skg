"""
skg.sensors.bloodhound_sensor
==============================
Native BloodHound CE sensor.

Pulls AD data directly from BloodHound Community Edition's REST API
(/api/v2/*) and routes through the existing BloodHound adapter for
wicket evaluation. No SharpHound drop directories needed.

BloodHound CE API endpoints used:
  POST /api/v2/login              — obtain JWT
  GET  /api/v2/users              — user objects
  GET  /api/v2/computers          — computer objects  
  GET  /api/v2/groups             — group objects
  GET  /api/v2/domains            — domain list + properties
  GET  /api/v2/pathfinding         — shortest attack paths (AD-10 through AD-15)
  GET  /api/v2/graph/cypher       — Cypher queries for specific conditions

Config (skg/config/sensors.yaml):
  bloodhound:
    enabled: true
    url: http://localhost:8080          # BH CE server
    username: admin
    password: "${BH_PASSWORD}"         # env var expansion
    domain_sid: "S-1-5-21-..."        # filter to specific domain (optional)
    collect_interval_s: 900            # 15 min default
    attack_path_id: ad_kerberoast_v1

Falls back to Cypher queries via Neo4j bolt if BH CE API is unavailable:
  neo4j_url: bolt://localhost:7687
  neo4j_user: neo4j
  neo4j_password: "${NEO4J_PASSWORD}"

The sensor normalizes BH CE API responses into the same dict structure
the BloodHound adapter (adapters/bloodhound/parse.py) expects, so no
adapter changes are needed.
"""
from __future__ import annotations

import json
import logging
import os
import uuid
import base64
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from skg.sensors import BaseSensor, register
from skg.sensors.adapter_runner import run_bloodhound
from skg_core.config.paths import SKG_STATE_DIR
try:
    from skg_services.gravity.event_writer import emit_events
except Exception:  # pragma: no cover - legacy fallback when canonical packages are unavailable
    from skg.sensors import emit_events

log = logging.getLogger("skg.sensors.bloodhound")

BH_STATE_FILE = SKG_STATE_DIR / "bloodhound_sensor.state.json"

# Cypher queries for conditions BH CE REST API doesn't expose directly
CYPHER_QUERIES = {
    "kerberoastable": """
        MATCH (u:User)
        WHERE u.hasspn = true AND u.enabled = true
        AND NOT u.name ENDS WITH '$'
        RETURN u.name AS name, u.objectid AS objectid,
               u.supportedencryptiontypes AS enc_types,
               u.dontreqpreauth AS dontreqpreauth,
               u.lastlogontimestamp AS lastlogon,
               u.description AS description
    """,
    "unconstrained_delegation": """
        MATCH (c:Computer)
        WHERE c.unconstraineddelegation = true
        AND c.enabled = true AND c.isdc = false
        RETURN c.name AS name, c.objectid AS objectid,
               c.lastlogontimestamp AS lastlogon,
               c.haslaps AS haslaps
    """,
    "constrained_delegation": """
        MATCH (n)
        WHERE n.allowedtodelegate IS NOT NULL
        AND size(n.allowedtodelegate) > 0
        RETURN n.name AS name, n.objectid AS objectid,
               n.allowedtodelegate AS spns,
               n.trustedtoauthfordelegation AS protocol_transition,
               labels(n) AS type
    """,
    "acl_edges": """
        MATCH (src)-[r:GenericAll|GenericWrite|WriteDacl|WriteOwner|
                      ForceChangePassword|GetChanges|GetChangesAll|
                      AddMember|AllExtendedRights|Owns]->(dst)
        WHERE NOT src.objectid = dst.objectid
        RETURN src.name AS principal_name,
               src.objectid AS principal_id,
               type(r) AS right_name,
               dst.name AS target_name,
               dst.objectid AS target_id,
               r.isinherited AS is_inherited
        LIMIT 5000
    """,
    "no_laps_workstations": """
        MATCH (c:Computer)
        WHERE c.haslaps = false AND c.enabled = true
        AND c.isdc = false
        RETURN c.name AS name, c.objectid AS objectid
    """,
    "password_in_description": """
        MATCH (n)
        WHERE n.description IS NOT NULL
        AND (toLower(n.description) CONTAINS 'password'
          OR toLower(n.description) CONTAINS 'passwd'
          OR toLower(n.description) CONTAINS 'pwd'
          OR toLower(n.description) CONTAINS 'cred'
          OR toLower(n.description) CONTAINS 'secret')
        RETURN n.name AS name, n.objectid AS objectid,
               n.description AS description,
               n.enabled AS enabled,
               labels(n) AS type
    """,
    "da_sessions": """
        MATCH (c:Computer)-[:HasSession]->(u:User)-[:MemberOf*1..]->(g:Group)
        WHERE g.name STARTS WITH 'DOMAIN ADMINS'
        RETURN c.name AS computer, u.name AS user,
               u.objectid AS user_id, c.objectid AS computer_id
    """,
    "domain_properties": """
        MATCH (d:Domain)
        RETURN d.name AS name, d.objectid AS objectid,
               d.minpwdlength AS minpwdlength,
               d.pwdproperties AS pwdproperties,
               d.functionallevel AS functionallevel
    """,
    "adminsdholder": """
        MATCH (src)-[r:GenericAll|GenericWrite|WriteDacl|WriteOwner|
                      AllExtendedRights]->(t)
        WHERE toLower(t.name) CONTAINS 'adminsdholder'
        RETURN src.name AS principal, src.objectid AS principal_id,
               type(r) AS right, t.name AS target
    """,
    "asrep_roastable": """
        MATCH (u:User)
        WHERE u.dontreqpreauth = true AND u.enabled = true
        RETURN u.name AS name, u.objectid AS objectid,
               u.lastlogontimestamp AS lastlogon
    """,
    "stale_da": """
        MATCH (u:User)-[:MemberOf*1..]->(g:Group)
        WHERE g.name STARTS WITH 'DOMAIN ADMINS'
        AND u.enabled = true
        AND u.lastlogontimestamp < (timestamp() / 1000 - 7776000)
        RETURN u.name AS name, u.objectid AS objectid,
               u.lastlogontimestamp AS lastlogon
    """,
}


class BloodHoundCEClient:
    """
    Thin REST client for BloodHound Community Edition API.
    Handles auth token lifecycle and pagination.
    """

    def __init__(self, url: str, username: str, password: str):
        self.base = url.rstrip("/")
        self.username = username
        self.password = password
        self._token: str | None = None
        self._token_expiry: float = 0.0

    def _headers(self) -> dict:
        if not self._token or datetime.now(timezone.utc).timestamp() > self._token_expiry:
            self._login()
        return {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }

    def _login(self):
        import urllib.request, urllib.error
        payload = json.dumps({
            "login_method": "secret",
            "username": self.username,
            "secret": self.password,
        }).encode()
        req = urllib.request.Request(
            f"{self.base}/api/v2/login",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                data = json.loads(r.read())
            self._token = data["data"]["session_token"]
            self._token_expiry = datetime.now(timezone.utc).timestamp() + 3500
            log.info(f"[bh] authenticated to {self.base}")
        except Exception as exc:
            raise RuntimeError(f"BloodHound CE login failed: {exc}") from exc

    def get(self, path: str, params: dict | None = None) -> dict:
        import urllib.request, urllib.parse
        url = f"{self.base}{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(url, headers=self._headers(), method="GET")
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())

    def paginate(self, path: str, limit: int = 500) -> list[dict]:
        """Collect all pages from a paginated BH CE endpoint."""
        results = []
        skip = 0
        while True:
            data = self.get(path, {"limit": limit, "skip": skip})
            items = (data.get("data") or {}).get("nodes") or data.get("data") or []
            if not items:
                break
            results.extend(items if isinstance(items, list) else [items])
            if len(items) < limit:
                break
            skip += limit
        return results

    def cypher(self, query: str) -> list[dict]:
        """Run a Cypher query via BH CE's graph endpoint."""
        import urllib.request
        payload = json.dumps({"query": query, "include_properties": True}).encode()
        req = urllib.request.Request(
            f"{self.base}/api/v2/graphs/cypher",
            data=payload,
            headers=self._headers(),
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                data = json.loads(r.read())
            # BH CE returns {data: {nodes: [], edges: []}} or {data: [...]}
            raw = data.get("data", {})
            if isinstance(raw, list):
                return raw
            return raw.get("nodes", []) + raw.get("edges", [])
        except Exception as exc:
            log.debug(f"[bh] cypher query failed: {exc}")
            return []


class Neo4jClient:
    """
    Fallback: direct Neo4j bolt connection when BH CE API unavailable.
    Requires neo4j Python driver: pip install neo4j
    """

    def __init__(self, url: str, user: str, password: str):
        self.url = url
        self.user = user
        self.password = password
        self._driver = None
        self._http_endpoint: str | None = None

    def _http_url(self) -> str:
        if self._http_endpoint:
            return self._http_endpoint
        url = self.url
        if url.startswith("bolt://"):
            url = "http://" + url[len("bolt://"):]
        elif url.startswith("neo4j://"):
            url = "http://" + url[len("neo4j://"):]
        elif not url.startswith(("http://", "https://")):
            url = f"http://{url}"
        if url.startswith(("http://", "https://")) and ":7687" in url:
            url = url.replace(":7687", ":7474", 1)
        self._http_endpoint = url.rstrip("/") + "/db/neo4j/tx/commit"
        return self._http_endpoint

    def _connect(self):
        if self._driver:
            return
        try:
            from neo4j import GraphDatabase
            self._driver = GraphDatabase.driver(
                self.url, auth=(self.user, self.password)
            )
        except ImportError:
            self._driver = None

    def query(self, cypher: str) -> list[dict]:
        self._connect()
        if self._driver:
            with self._driver.session() as session:
                result = session.run(cypher)
                return [dict(record) for record in result]
        return self._query_http(cypher)

    def _query_http(self, cypher: str) -> list[dict]:
        import urllib.request

        payload = json.dumps({
            "statements": [{"statement": cypher, "resultDataContents": ["row"]}]
        }).encode()
        auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
        req = urllib.request.Request(
            self._http_url(),
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Basic {auth}",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read())
        errors = data.get("errors") or []
        if errors:
            raise RuntimeError(f"neo4j HTTP query failed: {errors[0].get('message', errors[0])}")
        results = []
        for stmt in data.get("results", []):
            columns = stmt.get("columns", [])
            for row in stmt.get("data", []):
                values = row.get("row", [])
                results.append(dict(zip(columns, values)))
        return results

    def close(self):
        if self._driver:
            self._driver.close()
            self._driver = None


def _normalize_bh_ce_users(raw_users: list[dict]) -> list[dict]:
    """Normalize BH CE user objects to BloodHound adapter format."""
    normalized = []
    for u in raw_users:
        props = u.get("properties", u)
        normalized.append({
            "Properties": {
                "name":                   props.get("name") or props.get("displayname", ""),
                "samaccountname":         props.get("samaccountname", ""),
                "enabled":                props.get("enabled", True),
                "hasspn":                 props.get("hasspn", False),
                "dontreqpreauth":         props.get("dontreqpreauth", False),
                "supportedencryptiontypes": props.get("supportedencryptiontypes", 0),
                "lastlogontimestamp":     props.get("lastlogontimestamp", -1),
                "description":            props.get("description", ""),
                "pwdlastset":             props.get("pwdlastset", -1),
            },
            "ObjectIdentifier": u.get("objectid") or props.get("objectid", ""),
        })
    return normalized


def _normalize_bh_ce_computers(raw_computers: list[dict]) -> list[dict]:
    """Normalize BH CE computer objects."""
    normalized = []
    for c in raw_computers:
        props = c.get("properties", c)
        normalized.append({
            "Properties": {
                "name":                  props.get("name", ""),
                "enabled":               props.get("enabled", True),
                "unconstraineddelegation": props.get("unconstraineddelegation", False),
                "isdc":                  props.get("isdc", False),
                "haslaps":               props.get("haslaps", False),
                "lastlogontimestamp":    props.get("lastlogontimestamp", -1),
                "operatingsystem":       props.get("operatingsystem", ""),
                "allowedtodelegate":     props.get("allowedtodelegate", []),
                "trustedtoauthfordelegation": props.get("trustedtoauthfordelegation", False),
            },
            "ObjectIdentifier": c.get("objectid") or props.get("objectid", ""),
        })
    return normalized


def _normalize_bh_ce_groups(raw_groups: list[dict]) -> list[dict]:
    """Normalize BH CE group objects."""
    normalized = []
    for g in raw_groups:
        props = g.get("properties", g)
        members = g.get("members", [])
        normalized.append({
            "Properties": {
                "name":        props.get("name", ""),
                "description": props.get("description", ""),
            },
            "ObjectIdentifier": g.get("objectid") or props.get("objectid", ""),
            "Members": [{"ObjectIdentifier": m.get("objectid", m) if isinstance(m, dict) else m}
                        for m in members],
        })
    return normalized


def _normalize_bh_ce_acls(raw_edges: list[dict]) -> list[dict]:
    """Normalize BH CE ACL/edge objects to BloodHound adapter format."""
    normalized = []
    for edge in raw_edges:
        # BH CE edge format: {source, target, label, properties}
        # or Cypher result: {principal_name, principal_id, right_name, target_id, ...}
        if "right_name" in edge:
            # Cypher result row
            normalized.append({
                "RightName":               edge.get("right_name", ""),
                "PrincipalName":           edge.get("principal_name", ""),
                "PrincipalObjectIdentifier": edge.get("principal_id", ""),
                "ObjectIdentifier":        edge.get("target_id", ""),
                "IsInherited":             edge.get("is_inherited", False),
            })
        else:
            # BH CE graph edge
            props = edge.get("properties", {})
            normalized.append({
                "RightName":               edge.get("label") or props.get("label", ""),
                "PrincipalObjectIdentifier": edge.get("source", ""),
                "PrincipalName":           props.get("principalname", ""),
                "ObjectIdentifier":        edge.get("target", ""),
                "IsInherited":             props.get("isinherited", False),
            })
    return normalized


def _normalize_bh_ce_domains(raw_domains: list[dict]) -> list[dict]:
    """Normalize BH CE domain objects."""
    normalized = []
    for d in raw_domains:
        props = d.get("properties", d)
        normalized.append({
            "Properties": {
                "name":            props.get("name", ""),
                "minpwdlength":    props.get("minpwdlength", 0),
                "pwdproperties":   props.get("pwdproperties", 0),
                "functionallevel": props.get("functionallevel", ""),
            },
            "ObjectIdentifier": d.get("objectid") or props.get("objectid", ""),
        })
    return normalized


def collect_via_api(client: BloodHoundCEClient, domain_sid: str | None = None) -> dict:
    """
    Pull all data needed by the BloodHound adapter from BH CE REST API.
    Returns normalized dict ready for adapter_runner.run_bloodhound().
    """
    log.info("[bh] collecting via BH CE REST API")

    # Pull object lists
    raw_users     = client.paginate("/api/v2/users")
    raw_computers = client.paginate("/api/v2/computers")
    raw_groups    = client.paginate("/api/v2/groups")

    # Domain properties — use Cypher for richer data
    raw_domains_cypher = client.cypher(CYPHER_QUERIES["domain_properties"])
    if not raw_domains_cypher:
        raw_domains = client.paginate("/api/v2/domains")
    else:
        raw_domains = raw_domains_cypher

    # ACL edges — Cypher required (REST API doesn't expose edges directly)
    raw_acls = client.cypher(CYPHER_QUERIES["acl_edges"])

    # Sessions for AD-22 (stale privileged account tiering)
    raw_sessions = client.cypher(CYPHER_QUERIES["da_sessions"])

    log.info(f"[bh] pulled: {len(raw_users)} users, {len(raw_computers)} computers, "
             f"{len(raw_groups)} groups, {len(raw_acls)} ACL edges, "
             f"{len(raw_sessions)} DA sessions")

    return {
        "users":     _normalize_bh_ce_users(raw_users),
        "computers": _normalize_bh_ce_computers(raw_computers),
        "groups":    _normalize_bh_ce_groups(raw_groups),
        "acls":      _normalize_bh_ce_acls(raw_acls),
        "domains":   _normalize_bh_ce_domains(raw_domains),
        "sessions":  raw_sessions,
    }


def collect_via_neo4j(client: Neo4jClient) -> dict:
    """
    Pull all data from Neo4j directly using Cypher.
    Used when BH CE API is unreachable but Neo4j bolt is accessible.
    """
    log.info("[bh] collecting via Neo4j bolt")

    def q(cypher):
        try:
            return client.query(cypher)
        except Exception as exc:
            log.warning(f"[bh] neo4j query failed: {exc}")
            return []

    raw_users = q("""
        MATCH (u:User) WHERE u.enabled = true
        RETURN u.name AS name, u.objectid AS objectid,
               u.samaccountname AS samaccountname,
               u.hasspn AS hasspn,
               u.dontreqpreauth AS dontreqpreauth,
               u.supportedencryptiontypes AS supportedencryptiontypes,
               u.lastlogontimestamp AS lastlogontimestamp,
               u.description AS description,
               u.enabled AS enabled
    """)

    raw_computers = q("""
        MATCH (c:Computer) WHERE c.enabled = true
        RETURN c.name AS name, c.objectid AS objectid,
               c.unconstraineddelegation AS unconstraineddelegation,
               c.isdc AS isdc, c.haslaps AS haslaps,
               c.lastlogontimestamp AS lastlogontimestamp,
               c.allowedtodelegate AS allowedtodelegate,
               c.trustedtoauthfordelegation AS trustedtoauthfordelegation,
               c.enabled AS enabled
    """)

    raw_groups = q("""
        MATCH (g:Group)
        OPTIONAL MATCH (m)-[:MemberOf]->(g)
        RETURN g.name AS name, g.objectid AS objectid,
               collect(m.objectid) AS member_ids
    """)

    raw_acls = q(CYPHER_QUERIES["acl_edges"])
    raw_domains = q(CYPHER_QUERIES["domain_properties"])
    raw_sessions = q(CYPHER_QUERIES["da_sessions"])

    log.info(f"[bh] neo4j pulled: {len(raw_users)} users, {len(raw_computers)} computers")

    # Normalize from Cypher row format
    def _user(row):
        return {
            "Properties": {k: row.get(k) for k in [
                "name","samaccountname","enabled","hasspn","dontreqpreauth",
                "supportedencryptiontypes","lastlogontimestamp","description",
            ]},
            "ObjectIdentifier": row.get("objectid", ""),
        }

    def _computer(row):
        return {
            "Properties": {k: row.get(k) for k in [
                "name","enabled","unconstraineddelegation","isdc","haslaps",
                "lastlogontimestamp","allowedtodelegate","trustedtoauthfordelegation",
            ]},
            "ObjectIdentifier": row.get("objectid", ""),
        }

    def _group(row):
        return {
            "Properties": {"name": row.get("name","")},
            "ObjectIdentifier": row.get("objectid",""),
            "Members": [{"ObjectIdentifier": oid}
                        for oid in (row.get("member_ids") or []) if oid],
        }

    def _domain(row):
        return {
            "Properties": {k: row.get(k) for k in
                           ["name","minpwdlength","pwdproperties","functionallevel"]},
            "ObjectIdentifier": row.get("objectid",""),
        }

    return {
        "users":     [_user(r) for r in raw_users],
        "computers": [_computer(r) for r in raw_computers],
        "groups":    [_group(r) for r in raw_groups],
        "acls":      _normalize_bh_ce_acls(raw_acls),
        "domains":   [_domain(r) for r in raw_domains],
        "sessions":  raw_sessions,
    }


def write_bh_dir(data: dict, bh_dir: Path):
    """Write normalized BH data to a directory for the adapter."""
    bh_dir.mkdir(parents=True, exist_ok=True)
    for key in ["users", "computers", "groups", "acls", "domains"]:
        items = data.get(key, [])
        # Write in BloodHound v4 format: {<type>: [...], count: N}
        (bh_dir / f"{key}.json").write_text(
            json.dumps({key: items, "count": len(items)}, indent=2)
        )
    # Sessions stored separately (not a standard BH file). The runtime seam
    # in skg.sensors.adapter_runner routes this evidence into canonical
    # AD-domain input shape for AD-22 migration readiness.
    sessions = data.get("sessions", [])
    if sessions:
        (bh_dir / "sessions.json").write_text(
            json.dumps({"sessions": sessions, "count": len(sessions)}, indent=2)
        )


@register("bloodhound")
class BloodHoundSensor(BaseSensor):
    """
    BloodHound CE native sensor.

    Connects to BH CE API or Neo4j bolt, pulls the full AD object graph,
    writes normalized JSON to a temp bh_dir, and routes through the
    existing BloodHound adapter for wicket evaluation.
    """
    name = "bloodhound"

    def __init__(self, cfg: dict, events_dir=None):
        super().__init__(cfg, events_dir=events_dir)
        self.url        = cfg.get("url", "http://localhost:8080")
        self.username   = cfg.get("username", "admin")
        self.password   = os.path.expandvars(cfg.get("password", ""))
        self.neo4j_url  = cfg.get("neo4j_url", "")
        self.neo4j_user = cfg.get("neo4j_user", "neo4j")
        self.neo4j_pass = os.path.expandvars(cfg.get("neo4j_password", ""))
        self.domain_sid = cfg.get("domain_sid")
        self.interval   = cfg.get("collect_interval_s", 900)
        self.attack_path_id = cfg.get("attack_path_id", "ad_kerberoast_v1")
        self._state     = self._load_state()

    def _load_state(self) -> dict:
        if BH_STATE_FILE.exists():
            try:
                return json.loads(BH_STATE_FILE.read_text())
            except Exception:
                pass
        return {"last_collected": 0, "last_run_id": None}

    def _save_state(self):
        BH_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        BH_STATE_FILE.write_text(json.dumps(self._state, indent=2))

    def _should_collect(self) -> bool:
        last = self._state.get("last_collected", 0)
        return (datetime.now(timezone.utc).timestamp() - last) >= self.interval

    def run(self) -> list[str]:
        if not self._should_collect():
            return []

        run_id = str(uuid.uuid4())
        workload_id = self.domain_sid or self.url.split("//")[-1].split(":")[0]

        # Try BH CE API first, fall back to Neo4j
        data = None

        if self.url and self.username and self.password:
            try:
                client = BloodHoundCEClient(self.url, self.username, self.password)
                data = collect_via_api(client, self.domain_sid)
            except Exception as exc:
                log.warning(f"[bh] CE API unavailable ({exc}), trying Neo4j")

        if data is None and self.neo4j_url:
            try:
                client = Neo4jClient(self.neo4j_url, self.neo4j_user, self.neo4j_pass)
                data = collect_via_neo4j(client)
                client.close()
            except Exception as exc:
                log.error(f"[bh] Neo4j also unavailable: {exc}")
                return []

        if data is None:
            log.error("[bh] no collection source available — configure url or neo4j_url")
            return []

        # Write to temp bh_dir and route through adapter
        bh_dir = SKG_STATE_DIR / "bh_cache" / run_id
        write_bh_dir(data, bh_dir)

        try:
            raw_events = run_bloodhound(bh_dir, workload_id, self.attack_path_id, run_id)
        except Exception as exc:
            log.error(f"[bh] adapter error: {exc}", exc_info=True)
            return []

        # Apply context calibration
        calibrated = []
        for ev in raw_events:
            p = ev.get("payload", {})
            wicket_id = p.get("wicket_id", "")
            domain    = "ad_lateral"
            rank      = ev.get("provenance", {}).get("evidence_rank", 1)
            base_conf = ev.get("provenance", {}).get("evidence", {}).get("confidence", 0.9)
            status    = p.get("status", "unknown")
            realized  = True if status == "realized" else (False if status == "blocked" else None)

            if self._ctx and wicket_id:
                et = f"{wicket_id}: {p.get('detail','')}"
                conf = self._ctx.calibrate(
                    base_conf,
                    et,
                    wicket_id,
                    domain,
                    workload_id,
                    source_id=ev.get("source", {}).get("source_id", ""),
                )
                ev["provenance"]["evidence"]["confidence"] = conf
                self._ctx.record(
                    evidence_text=et, wicket_id=wicket_id, domain=domain,
                    source_kind="bloodhound_api", evidence_rank=rank,
                    sensor_realized=realized, confidence=conf, workload_id=workload_id,
                )
            calibrated.append(ev)

        all_ids: list[str] = []
        if calibrated:
            ids = emit_events(calibrated, self.events_dir, f"bh_{workload_id}")
            all_ids.extend(ids)
            log.info(f"[bh] {workload_id}: {len(calibrated)} events emitted")

        self._state["last_collected"] = datetime.now(timezone.utc).timestamp()
        self._state["last_run_id"]    = run_id
        self._save_state()
        return all_ids
