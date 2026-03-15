"""
skg-web-toolchain :: adapters/web_active/auth_scanner.py

Authenticated web scanner. Handles CSRF-protected login forms,
maintains session cookies, and crawls post-authentication surfaces
to resolve wickets that are unknown from unauthenticated scanning.

This is the second-pass scanner. The collector (collector.py) does
unauthenticated recon. When it finds a login form (WB-06 realized)
but can't test injection because forms are behind auth, this module
takes over.

Usage:
  python auth_scanner.py --target http://172.17.0.2 \\
                         --username admin --password password \\
                         --out /tmp/auth_events.ndjson \\
                         --attack-path-id web_sqli_to_shell_v1

  # Or auto-detect creds from default list
  python auth_scanner.py --target http://172.17.0.2 \\
                         --out /tmp/auth_events.ndjson \\
                         --try-defaults
"""

import argparse
import json
import uuid
import re
import time
import html.parser
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin, urlencode, parse_qs
from typing import Optional

from transport import HttpTransport
from collector import (
    emit, parse_html, FormParser,
    SQLI_ERROR_PATTERNS, XSS_CANARY, XSS_PAYLOADS,
    TRAVERSAL_PAYLOADS, CMDI_PAYLOADS, SSTI_PAYLOADS,
    VERBOSE_ERROR_PATTERNS, DEFAULT_CREDS,
)


# ── Session management ───────────────────────────────────────────────────

class WebSession:
    """
    Manages HTTP session with cookie persistence and CSRF token extraction.
    """

    def __init__(self, transport: HttpTransport, base_url: str):
        self.transport = transport
        self.base_url = base_url.rstrip("/")
        self.cookies = {}
        self.csrf_token = None
        self.csrf_field_name = None
        self.authenticated = False
        self.auth_user = None

    def _merge_cookies(self, resp):
        """Extract Set-Cookie headers and merge into session."""
        raw = resp.raw_headers
        for line in raw.splitlines():
            if line.lower().startswith("set-cookie:"):
                cookie_part = line.split(":", 1)[1].strip()
                # Get just name=value before any ;
                nv = cookie_part.split(";")[0].strip()
                if "=" in nv:
                    name, val = nv.split("=", 1)
                    self.cookies[name.strip()] = val.strip()

    def _cookie_header(self) -> str:
        """Format cookies for Cookie header."""
        return "; ".join(f"{k}={v}" for k, v in self.cookies.items())

    def _extract_csrf(self, html_text: str) -> tuple:
        """
        Extract CSRF token from HTML.
        Looks for hidden inputs with common CSRF field names.
        Returns (field_name, token_value) or (None, None).
        """
        csrf_names = [
            "user_token", "csrf_token", "csrfmiddlewaretoken",
            "_token", "authenticity_token", "csrf", "__RequestVerificationToken",
            "_csrf_token", "token", "nonce",
        ]

        # Try both single and double quote patterns
        for quote_char in ("'", '"'):
            for name in csrf_names:
                # Pattern: name='field_name' ... value='token_value'
                pattern = (
                    rf'name={quote_char}{re.escape(name)}{quote_char}'
                    rf'[^>]*value={quote_char}([^{quote_char}]+){quote_char}'
                )
                match = re.search(pattern, html_text, re.IGNORECASE)
                if match:
                    return name, match.group(1)

                # Reversed order: value first, then name
                pattern2 = (
                    rf'value={quote_char}([^{quote_char}]+){quote_char}'
                    rf'[^>]*name={quote_char}{re.escape(name)}{quote_char}'
                )
                match2 = re.search(pattern2, html_text, re.IGNORECASE)
                if match2:
                    return name, match2.group(1)

        return None, None

    def get(self, path: str, follow_redirects: bool = True) -> "HttpTransport.HttpResponse":
        """GET with session cookies."""
        url = self.base_url + path if path.startswith("/") else path
        headers = {}
        if self.cookies:
            headers["Cookie"] = self._cookie_header()

        if follow_redirects:
            resp = self.transport.request_follow("GET", url, headers=headers)
        else:
            resp = self.transport.request("GET", url, headers=headers)

        self._merge_cookies(resp)
        return resp

    def post(self, path: str, data: dict,
             follow_redirects: bool = True) -> "HttpTransport.HttpResponse":
        """POST with session cookies and form data."""
        url = self.base_url + path if path.startswith("/") else path
        body = urlencode(data).encode()
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }
        if self.cookies:
            headers["Cookie"] = self._cookie_header()

        if follow_redirects:
            resp = self.transport.request_follow("POST", url, headers=headers, body=body)
        else:
            resp = self.transport.request("POST", url, headers=headers, body=body)

        self._merge_cookies(resp)
        return resp

    def login(self, login_path: str, username: str, password: str,
              user_field: str = None, pass_field: str = None) -> bool:
        """
        Attempt login with CSRF handling.
        1. GET login page to get session cookie + CSRF token
        2. POST credentials with token
        3. Verify authentication succeeded
        """
        # Step 1: GET login page
        resp = self.get(login_path)
        if resp.error:
            return False

        # Extract CSRF token
        csrf_name, csrf_value = self._extract_csrf(resp.text)
        if csrf_name:
            self.csrf_field_name = csrf_name
            self.csrf_token = csrf_value

        # Find form fields if not specified
        if not user_field or not pass_field:
            parsed = parse_html(resp.text)
            for form in parsed.forms:
                for inp in form["inputs"]:
                    if inp["type"] == "password" and not pass_field:
                        pass_field = inp["name"]
                    elif inp["type"] in ("text", "email") and not user_field:
                        if inp["name"]:
                            user_field = inp["name"]

        if not user_field:
            user_field = "username"
        if not pass_field:
            pass_field = "password"

        # Step 2: POST login
        login_data = {
            user_field: username,
            pass_field: password,
        }

        # Add CSRF token
        if csrf_name and csrf_value:
            login_data[csrf_name] = csrf_value

        # Add common submit button names
        login_data["Login"] = "Login"

        resp = self.post(login_path, login_data)
        if resp.error:
            return False

        # Step 3: Verify — check for auth success indicators
        auth_indicators = [
            "logout", "sign out", "log out", "dashboard",
            "welcome", "my account", "profile", "home",
        ]
        auth_failure_indicators = [
            "login failed", "invalid", "incorrect", "wrong password",
            "authentication failed", "bad credentials",
        ]

        text_lower = resp.text.lower()

        # Check for failure first
        for indicator in auth_failure_indicators:
            if indicator in text_lower:
                return False

        # Check for success
        for indicator in auth_indicators:
            if indicator in text_lower:
                self.authenticated = True
                self.auth_user = username
                return True

        # If we got redirected away from login page, probably success
        if hasattr(resp, 'redirect_chain') and len(getattr(resp, 'redirect_chain', [])) > 1:
            if login_path not in (getattr(resp, 'redirect_chain', [""]))[-1]:
                self.authenticated = True
                self.auth_user = username
                return True

        return False

    def try_default_creds(self, login_path: str) -> tuple:
        """Try all default credential pairs. Returns (username, password) or (None, None)."""
        for username, password in DEFAULT_CREDS:
            if self.login(login_path, username, password):
                return username, password
            # Reset session for next attempt
            self.cookies = {}
            self.authenticated = False
        return None, None


# ── Authenticated crawling ───────────────────────────────────────────────

def crawl_authenticated(session: WebSession, base_url: str,
                        max_pages: int = 50) -> dict:
    """
    Crawl the authenticated surface.
    Returns dict of discovered pages, forms, and parameters.
    """
    base = base_url.rstrip("/")
    visited = set()
    to_visit = [base + "/"]
    all_forms = []
    all_links = []
    all_params = set()

    while to_visit and len(visited) < max_pages:
        url = to_visit.pop(0)
        if url in visited:
            continue
        visited.add(url)

        # Only follow links on the same host
        up = urlparse(url)
        bp = urlparse(base)
        # Never follow logout links — destroys the session
        if any(x in url.lower() for x in ("logout", "signout", "sign_out", "log_out")):
            continue
        if up.hostname != bp.hostname:
            continue

        resp = session.get(url)
        if resp.error or resp.status != 200:
            continue

        ct = resp.header("content-type", "")
        if "html" not in ct:
            continue

        parsed = parse_html(resp.text)

        # Collect forms
        for form in parsed.forms:
            form["page"] = url
            action = form.get("action", "")
            form["resolved_action"] = urljoin(url, action) if action else url
            all_forms.append(form)

            for inp in form["inputs"]:
                if inp["name"]:
                    all_params.add(inp["name"])

        # Collect links for further crawling
        for link in parsed.links:
            resolved = urljoin(url, link)
            rp = urlparse(resolved)
            if rp.hostname == bp.hostname and resolved not in visited:
                to_visit.append(resolved)
                all_links.append(resolved)
                if rp.query:
                    for k in parse_qs(rp.query):
                        all_params.add(k)

    return {
        "pages_visited": list(visited),
        "forms": all_forms,
        "links": list(set(all_links)),
        "params": list(all_params),
    }


# ── Authenticated injection testing ─────────────────────────────────────

def test_sqli_authed(session: WebSession, form: dict,
                     out: Path, attack_path_id: str,
                     run_id: str, workload_id: str) -> bool:
    """Test a form for SQLi using the authenticated session."""
    action_url = form.get("resolved_action", "")
    method = form.get("method", "GET")
    params = [i for i in form["inputs"]
              if i["name"] and i["type"] not in ("submit", "hidden", "button", "password")]

    for param in params:
        pname = param["name"]

        # Error-based: single quote
        test_data = {pname: "1'"}
        # Include other form fields with benign values
        for other in form["inputs"]:
            if other["name"] and other["name"] != pname:
                test_data[other["name"]] = other.get("value", "test")

        # Add CSRF token if we have one
        if session.csrf_field_name and session.csrf_token:
            # Re-fetch to get fresh token
            page_resp = session.get(form.get("page", "/"))
            csrf_name, csrf_value = session._extract_csrf(page_resp.text)
            if csrf_name:
                test_data[csrf_name] = csrf_value

        if method.upper() == "POST":
            resp = session.post(action_url, test_data)
        else:
            url = (action_url if action_url and not action_url.endswith("#") else form.get("page", action_url).split("?")[0]) + "?" + urlencode(test_data)
            resp = session.get(url)

        if resp.error:
            continue

        for pat in SQLI_ERROR_PATTERNS:
            if pat.search(resp.text):
                emit(out, "WB-09", "realized", 1, "runtime",
                     f"{action_url} param={pname} (authenticated)",
                     0.9, attack_path_id, run_id, workload_id,
                     {"detail": f"SQLi via {pname} on {form.get('page', '?')} (authed session)"})
                return True

        # Boolean-based
        true_data = dict(test_data)
        true_data[pname] = "1' OR '1'='1"
        false_data = dict(test_data)
        false_data[pname] = "1' OR '1'='2"

        if method.upper() == "POST":
            resp_t = session.post(action_url, true_data)
            resp_f = session.post(action_url, false_data)
        else:
            resp_t = session.get((action_url if action_url and not action_url.endswith("#") else form.get("page", action_url).split("?")[0]) + "?" + urlencode(true_data))
            resp_f = session.get((action_url if action_url and not action_url.endswith("#") else form.get("page", action_url).split("?")[0]) + "?" + urlencode(false_data))

        if (not resp_t.error and not resp_f.error and
                abs(len(resp_t.body) - len(resp_f.body)) > 50):
            emit(out, "WB-09", "realized", 1, "runtime",
                 f"{action_url} param={pname} boolean (authenticated)",
                 0.85, attack_path_id, run_id, workload_id,
                 {"detail": f"Boolean SQLi via {pname}: "
                  f"{len(resp_t.body)} vs {len(resp_f.body)} bytes"})
            return True

    return False


def test_cmdi_authed(session: WebSession, form: dict,
                     out: Path, attack_path_id: str,
                     run_id: str, workload_id: str) -> bool:
    """Test a form for command injection."""
    action_url = form.get("resolved_action", "")
    method = form.get("method", "GET")
    params = [i for i in form["inputs"]
              if i["name"] and i["type"] not in ("submit", "hidden", "button", "password")]

    for param in params[:3]:
        pname = param["name"]

        # Baseline
        base_data = {pname: "127.0.0.1"}
        for other in form["inputs"]:
            if other["name"] and other["name"] != pname:
                base_data[other["name"]] = other.get("value", "test")

        if session.csrf_field_name:
            page_resp = session.get(form.get("page", "/"))
            cn, cv = session._extract_csrf(page_resp.text)
            if cn:
                base_data[cn] = cv

        if method.upper() == "POST":
            resp_base = session.post(action_url, base_data)
        else:
            resp_base = session.get((action_url if action_url and not action_url.endswith("#") else form.get("page", action_url).split("?")[0]) + "?" + urlencode(base_data))

        if resp_base.error:
            continue

        # Time-based command injection
        for payload, delay in [("; sleep 3", 3.0), ("| sleep 3", 3.0), ("&& sleep 3", 3.0)]:
            cmdi_data = dict(base_data)
            cmdi_data[pname] = "127.0.0.1" + payload

            if session.csrf_field_name:
                page_resp = session.get(form.get("page", "/"))
                cn, cv = session._extract_csrf(page_resp.text)
                if cn:
                    cmdi_data[cn] = cv

            if method.upper() == "POST":
                resp = session.post(action_url, cmdi_data)
            else:
                resp = session.get((action_url if action_url and not action_url.endswith("#") else form.get("page", action_url).split("?")[0]) + "?" + urlencode(cmdi_data))

            if not resp.error and resp.elapsed_ms > resp_base.elapsed_ms + (delay * 800):
                emit(out, "WB-14", "realized", 1, "runtime",
                     f"{action_url} param={pname} (authenticated)",
                     0.85, attack_path_id, run_id, workload_id,
                     {"detail": f"Command injection via {pname}: "
                      f"{resp.elapsed_ms:.0f}ms vs {resp_base.elapsed_ms:.0f}ms"})
                return True

        # Output-based: look for command output in response
        for payload in ["; id", "| id", "&& id", "$(id)", "`id`"]:
            cmdi_data = dict(base_data)
            cmdi_data[pname] = "127.0.0.1" + payload

            if session.csrf_field_name:
                page_resp = session.get(form.get("page", "/"))
                cn, cv = session._extract_csrf(page_resp.text)
                if cn:
                    cmdi_data[cn] = cv

            if method.upper() == "POST":
                resp = session.post(action_url, cmdi_data)
            else:
                resp = session.get((action_url if action_url and not action_url.endswith("#") else form.get("page", action_url).split("?")[0]) + "?" + urlencode(cmdi_data))

            if not resp.error and re.search(r"uid=\d+", resp.text):
                emit(out, "WB-14", "realized", 1, "runtime",
                     f"{action_url} param={pname} output (authenticated)",
                     0.95, attack_path_id, run_id, workload_id,
                     {"detail": f"Command injection confirmed: uid= in response via {pname}"})
                return True

    return False


def test_xss_authed(session: WebSession, form: dict,
                    out: Path, attack_path_id: str,
                    run_id: str, workload_id: str) -> bool:
    """Test a form for reflected XSS."""
    action_url = form.get("resolved_action", "")
    method = form.get("method", "GET")
    params = [i for i in form["inputs"]
              if i["name"] and i["type"] not in ("submit", "hidden", "button", "password")]

    canary = "skg7x7x7"
    for param in params[:3]:
        pname = param["name"]
        test_data = {pname: f"<{canary}>"}
        for other in form["inputs"]:
            if other["name"] and other["name"] != pname:
                test_data[other["name"]] = other.get("value", "test")

        if method.upper() == "POST":
            resp = session.post(action_url, test_data)
        else:
            resp = session.get((action_url if action_url and not action_url.endswith("#") else form.get("page", action_url).split("?")[0]) + "?" + urlencode(test_data))

        if not resp.error and f"<{canary}>" in resp.text:
            emit(out, "WB-11", "realized", 1, "runtime",
                 f"{action_url} param={pname} (authenticated)",
                 0.85, attack_path_id, run_id, workload_id,
                 {"detail": f"Reflected XSS via {pname} (authed session)"})
            return True

    return False


# ── Main authenticated scan ──────────────────────────────────────────────

def auth_scan(target: str, out_path: str, attack_path_id: str,
              username: str = None, password: str = None,
              login_path: str = None, try_defaults: bool = False,
              proxy: str = None, run_id: str = None,
              workload_id: str = None, timeout: float = 10.0):
    """
    Run authenticated scanning against a target.
    """
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    rid = run_id or str(uuid.uuid4())
    wid = workload_id or urlparse(target).hostname or "unknown"
    transport = HttpTransport(proxy=proxy, timeout=timeout)
    session = WebSession(transport, target)

    print(f"[SKG-AUTH] Target:  {target}")
    print(f"[SKG-AUTH] Output:  {out}")
    print(f"[SKG-AUTH] Run-ID:  {rid[:8]}")
    print()

    # Find login path if not specified
    if not login_path:
        # Try common login paths
        for path in ["/login.php", "/login", "/login.html", "/signin",
                     "/ui/login", "/wp-login.php", "/user/login",
                     "/auth/login", "/Account/Login"]:
            resp = transport.request("GET", target.rstrip("/") + path)
            if not resp.error and resp.status in (200, 301, 302):
                login_path = path
                break

        if not login_path:
            # Follow redirect from root
            resp = transport.request_follow("GET", target)
            if hasattr(resp, 'redirect_chain') and len(resp.redirect_chain) > 1:
                final = urlparse(resp.redirect_chain[-1])
                login_path = final.path
            else:
                login_path = "/"

    print(f"[SKG-AUTH] Login:   {login_path}")

    # Authenticate
    if try_defaults and not (username and password):
        print("[SKG-AUTH] Trying default credentials...")
        username, password = session.try_default_creds(login_path)
        if username:
            print(f"[SKG-AUTH] Default creds accepted: {username}:{password}")
            emit(out, "WB-08", "realized", 1, "runtime",
                 f"{target}{login_path}", 0.95,
                 attack_path_id, rid, wid,
                 {"detail": f"Default creds accepted: {username}:{password} (with CSRF handling)"})
        else:
            print("[SKG-AUTH] No default credentials worked")
            emit(out, "WB-08", "blocked", 1, "runtime",
                 f"{target}{login_path}", 0.8,
                 attack_path_id, rid, wid,
                 {"detail": "All default credential pairs rejected (CSRF-aware testing)"})
            return
    elif username and password:
        if session.login(login_path, username, password):
            print(f"[SKG-AUTH] Authenticated as {username}")
            emit(out, "WB-08", "realized", 1, "runtime",
                 f"{target}{login_path}", 0.95,
                 attack_path_id, rid, wid,
                 {"detail": f"Creds accepted: {username}:{password} (with CSRF handling)"})
        else:
            print(f"[SKG-AUTH] Login failed for {username}")
            return
    else:
        print("[!] No credentials provided and --try-defaults not set")
        return

    if not session.authenticated:
        print("[!] Not authenticated, cannot proceed")
        return

    # Crawl authenticated surface
    print("\n[SKG-AUTH] Crawling authenticated surface...")
    crawl_result = crawl_authenticated(session, target)
    print(f"  Pages:  {len(crawl_result['pages_visited'])}")
    print(f"  Forms:  {len(crawl_result['forms'])}")
    print(f"  Links:  {len(crawl_result['links'])}")
    print(f"  Params: {len(crawl_result['params'])}")

    # Test injection on discovered forms
    sqli_found = False
    cmdi_found = False
    xss_found = False

    print("\n[SKG-AUTH] Testing injection on authenticated forms...")
    for i, form in enumerate(crawl_result["forms"]):
        page = form.get("page", "?")
        params = [inp["name"] for inp in form["inputs"]
                  if inp["name"] and inp["type"] not in ("submit", "hidden", "button")]
        if not params:
            continue

        print(f"  Form {i+1}: {page} [{form.get('method', '?')}] params={params}")

        if not sqli_found:
            if test_sqli_authed(session, form, out, attack_path_id, rid, wid):
                sqli_found = True
                print(f"    → SQLi FOUND")

        if not cmdi_found:
            if test_cmdi_authed(session, form, out, attack_path_id, rid, wid):
                cmdi_found = True
                print(f"    → Command Injection FOUND")

        if not xss_found:
            if test_xss_authed(session, form, out, attack_path_id, rid, wid):
                xss_found = True
                print(f"    → XSS FOUND")

    # Emit unknowns for things we didn't find
    if not sqli_found:
        emit(out, "WB-09", "unknown", 1, "runtime",
             f"{target} authed scan", 0.5,
             attack_path_id, rid, wid,
             {"detail": f"Tested {len(crawl_result['forms'])} authed forms, no SQLi"})

    if not cmdi_found:
        emit(out, "WB-14", "unknown", 1, "runtime",
             f"{target} authed scan", 0.5,
             attack_path_id, rid, wid,
             {"detail": f"No command injection in authed forms"})

    if not xss_found:
        emit(out, "WB-11", "unknown", 1, "runtime",
             f"{target} authed scan", 0.5,
             attack_path_id, rid, wid,
             {"detail": f"No XSS in authed forms"})

    # Summary
    event_count = sum(1 for _ in open(out))
    print(f"\n[SKG-AUTH] Complete. {event_count} events in {out}")
    findings = []
    if sqli_found: findings.append("SQLi")
    if cmdi_found: findings.append("CMDI")
    if xss_found: findings.append("XSS")
    print(f"[SKG-AUTH] Findings: {', '.join(findings) if findings else 'none'}")


def main():
    parser = argparse.ArgumentParser(
        description="SKG Authenticated Web Scanner")
    parser.add_argument("--target", required=True)
    parser.add_argument("--username", default=None)
    parser.add_argument("--password", default=None)
    parser.add_argument("--login-path", dest="login_path", default=None)
    parser.add_argument("--try-defaults", dest="try_defaults", action="store_true")
    parser.add_argument("--out", required=True)
    parser.add_argument("--attack-path-id", dest="attack_path_id",
                        default="web_sqli_to_shell_v1")
    parser.add_argument("--proxy", default=None)
    parser.add_argument("--run-id", dest="run_id", default=None)
    parser.add_argument("--workload-id", dest="workload_id", default=None)
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()

    auth_scan(
        target=args.target,
        out_path=args.out,
        attack_path_id=args.attack_path_id,
        username=args.username,
        password=args.password,
        login_path=args.login_path,
        try_defaults=args.try_defaults,
        proxy=args.proxy,
        run_id=args.run_id,
        workload_id=args.workload_id,
        timeout=args.timeout,
    )


if __name__ == "__main__":
    main()
