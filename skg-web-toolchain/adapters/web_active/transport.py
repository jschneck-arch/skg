"""
skg-web-toolchain :: transport.py

HTTP transport layer with optional SOCKS proxy support.
The collector logic calls transport methods and never knows
whether the connection is direct or proxied.

Proxy support:
  SOCKS5: socks5://127.0.0.1:1080  (e.g. SSH dynamic forward, chisel)
  SOCKS4: socks4://127.0.0.1:1080
  HTTP:   http://127.0.0.1:8080     (e.g. burp, mitmproxy)

Usage:
  from transport import HttpTransport
  t = HttpTransport(proxy="socks5://127.0.0.1:1080", timeout=10)
  resp = t.request("GET", "http://192.168.1.50/")
  print(resp.status, resp.headers, resp.body[:200])
"""

import socket
import ssl
import struct
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse


@dataclass
class HttpResponse:
    status: int = 0
    reason: str = ""
    headers: dict = field(default_factory=dict)
    raw_headers: str = ""
    body: bytes = b""
    elapsed_ms: float = 0.0
    error: Optional[str] = None

    @property
    def text(self) -> str:
        try:
            return self.body.decode("utf-8", errors="replace")
        except Exception:
            return self.body.decode("latin-1", errors="replace")

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)


def _socks5_connect(sock: socket.socket, host: str, port: int):
    """SOCKS5 handshake — no-auth only."""
    sock.sendall(b"\x05\x01\x00")
    resp = sock.recv(2)
    if resp != b"\x05\x00":
        raise ConnectionError(f"SOCKS5 auth failed: {resp.hex()}")

    # Connect request
    addr = host.encode("utf-8")
    req = b"\x05\x01\x00\x03" + bytes([len(addr)]) + addr + struct.pack("!H", port)
    sock.sendall(req)

    resp = sock.recv(4)
    if resp[1] != 0:
        codes = {1: "general failure", 2: "not allowed", 3: "network unreachable",
                 4: "host unreachable", 5: "connection refused", 6: "TTL expired",
                 7: "command not supported", 8: "address type not supported"}
        raise ConnectionError(f"SOCKS5 connect failed: {codes.get(resp[1], resp[1])}")

    # Consume bound address
    atyp = resp[3]
    if atyp == 1:      # IPv4
        sock.recv(4 + 2)
    elif atyp == 3:    # Domain
        dlen = sock.recv(1)[0]
        sock.recv(dlen + 2)
    elif atyp == 4:    # IPv6
        sock.recv(16 + 2)


def _socks4_connect(sock: socket.socket, host: str, port: int):
    """SOCKS4a connect (supports domain names)."""
    req = b"\x04\x01" + struct.pack("!H", port) + b"\x00\x00\x00\x01" + b"\x00"
    req += host.encode("utf-8") + b"\x00"
    sock.sendall(req)
    resp = sock.recv(8)
    if resp[1] != 0x5a:
        raise ConnectionError(f"SOCKS4 connect failed: status {resp[1]:#x}")


class HttpTransport:
    """
    Raw HTTP client with SOCKS/HTTP proxy support.
    No external dependencies beyond stdlib.
    """

    def __init__(self, proxy: Optional[str] = None, timeout: float = 10.0,
                 verify_ssl: bool = False, max_body: int = 2 * 1024 * 1024):
        self.proxy = proxy
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.max_body = max_body

        self._proxy_type = None
        self._proxy_host = None
        self._proxy_port = None

        if proxy:
            p = urlparse(proxy)
            self._proxy_type = p.scheme.lower()
            self._proxy_host = p.hostname
            self._proxy_port = p.port or (1080 if "socks" in self._proxy_type else 8080)

    def _raw_connect(self, host: str, port: int, use_tls: bool) -> socket.socket:
        """Establish a TCP connection, optionally through a proxy, optionally with TLS."""
        if self._proxy_type and self._proxy_type.startswith("socks"):
            sock = socket.create_connection((self._proxy_host, self._proxy_port),
                                           timeout=self.timeout)
            if self._proxy_type == "socks5":
                _socks5_connect(sock, host, port)
            elif self._proxy_type == "socks4":
                _socks4_connect(sock, host, port)
            else:
                raise ValueError(f"Unsupported proxy type: {self._proxy_type}")
        else:
            sock = socket.create_connection((host, port), timeout=self.timeout)

        sock.settimeout(self.timeout)

        if use_tls:
            ctx = ssl.create_default_context()
            if not self.verify_ssl:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)

        return sock

    def request(self, method: str, url: str,
                headers: Optional[dict] = None,
                body: Optional[bytes] = None) -> HttpResponse:
        """
        Send an HTTP request and return the response.
        Handles chunked transfer encoding and Content-Length.
        """
        import time
        start = time.monotonic()

        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        host = parsed.hostname
        port = parsed.port or (443 if scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        use_tls = scheme == "https"

        # Handle HTTP proxy (CONNECT method for HTTPS, direct for HTTP)
        if self._proxy_type == "http" and use_tls:
            return self._http_proxy_connect(method, url, host, port, path,
                                            headers, body, start)
        elif self._proxy_type == "http" and not use_tls:
            # For HTTP proxy with plain HTTP, send full URL as path
            path = url

        try:
            sock = self._raw_connect(host, port, use_tls)
        except Exception as e:
            return HttpResponse(error=f"connect: {e}",
                                elapsed_ms=(time.monotonic() - start) * 1000)

        try:
            return self._do_request(sock, method, host, port, path,
                                    headers, body, start)
        except Exception as e:
            return HttpResponse(error=f"request: {e}",
                                elapsed_ms=(time.monotonic() - start) * 1000)
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _http_proxy_connect(self, method, url, host, port, path,
                            headers, body, start):
        """HTTP CONNECT tunnel for HTTPS through HTTP proxy."""
        import time
        try:
            sock = socket.create_connection((self._proxy_host, self._proxy_port),
                                           timeout=self.timeout)
            sock.settimeout(self.timeout)

            connect_req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
            sock.sendall(connect_req.encode())

            resp_line = b""
            while b"\r\n\r\n" not in resp_line:
                resp_line += sock.recv(4096)

            if b"200" not in resp_line.split(b"\r\n")[0]:
                return HttpResponse(error=f"CONNECT failed: {resp_line[:100]}",
                                    elapsed_ms=(time.monotonic() - start) * 1000)

            ctx = ssl.create_default_context()
            if not self.verify_ssl:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)

            return self._do_request(sock, method, host, port, path,
                                    headers, body, start)
        except Exception as e:
            return HttpResponse(error=f"proxy_connect: {e}",
                                elapsed_ms=(time.monotonic() - start) * 1000)

    def _do_request(self, sock, method, host, port, path,
                    headers, body, start):
        """Build and send HTTP/1.1 request, parse response."""
        import time

        hdrs = {
            "Host": host if port in (80, 443) else f"{host}:{port}",
            "User-Agent": "Mozilla/5.0 (compatible)",
            "Accept": "*/*",
            "Connection": "close",
        }
        if headers:
            for k, v in headers.items():
                hdrs[k] = v
        if body:
            hdrs["Content-Length"] = str(len(body))

        req_lines = [f"{method.upper()} {path} HTTP/1.1"]
        for k, v in hdrs.items():
            req_lines.append(f"{k}: {v}")
        req_lines.append("")
        req_lines.append("")
        raw_req = "\r\n".join(req_lines).encode("utf-8")
        if body:
            raw_req += body

        sock.sendall(raw_req)

        # Read response
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk

        if b"\r\n\r\n" not in buf:
            return HttpResponse(error="incomplete headers",
                                elapsed_ms=(time.monotonic() - start) * 1000)

        header_part, body_part = buf.split(b"\r\n\r\n", 1)
        header_lines = header_part.decode("utf-8", errors="replace").split("\r\n")

        # Parse status line
        status_match = re.match(r"HTTP/[\d.]+\s+(\d+)\s*(.*)", header_lines[0])
        status = int(status_match.group(1)) if status_match else 0
        reason = status_match.group(2).strip() if status_match else ""

        # Parse headers — use list for Set-Cookie so multiple cookies aren't lost
        resp_headers = {}
        _set_cookies = []
        for line in header_lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                kl = k.strip().lower()
                if kl == "set-cookie":
                    _set_cookies.append(v.strip())
                else:
                    resp_headers[kl] = v.strip()
        if _set_cookies:
            resp_headers["set-cookie"] = _set_cookies  # list of cookie strings

        # Read body
        content_length = resp_headers.get("content-length")
        transfer_encoding = resp_headers.get("transfer-encoding", "").lower()

        if transfer_encoding == "chunked":
            body_data = self._read_chunked(sock, body_part)
        elif content_length:
            needed = int(content_length) - len(body_part)
            body_data = body_part
            while needed > 0:
                chunk = sock.recv(min(needed, 65536))
                if not chunk:
                    break
                body_data += chunk
                needed -= len(chunk)
        else:
            # Read until close
            body_data = body_part
            while len(body_data) < self.max_body:
                try:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    body_data += chunk
                except (socket.timeout, ssl.SSLError):
                    break

        elapsed = (time.monotonic() - start) * 1000

        return HttpResponse(
            status=status,
            reason=reason,
            headers=resp_headers,
            raw_headers=header_part.decode("utf-8", errors="replace"),
            body=body_data[:self.max_body],
            elapsed_ms=elapsed,
        )

    def _read_chunked(self, sock, initial: bytes) -> bytes:
        """Read chunked transfer encoding."""
        buf = initial
        result = b""

        while True:
            # Find chunk size line
            while b"\r\n" not in buf:
                chunk = sock.recv(4096)
                if not chunk:
                    return result + buf
                buf += chunk

            size_line, buf = buf.split(b"\r\n", 1)
            try:
                chunk_size = int(size_line.strip(), 16)
            except ValueError:
                return result + buf

            if chunk_size == 0:
                break

            # Read chunk data
            while len(buf) < chunk_size + 2:  # +2 for trailing \r\n
                data = sock.recv(min(chunk_size + 2 - len(buf), 65536))
                if not data:
                    return result + buf
                buf += data

            result += buf[:chunk_size]
            buf = buf[chunk_size + 2:]

            if len(result) > 2 * 1024 * 1024:
                break

        return result


    def request_follow(self, method: str, url: str,
                       headers: Optional[dict] = None,
                       body: Optional[bytes] = None,
                       max_redirects: int = 5) -> "HttpResponse":
        """
        Send an HTTP request and follow redirects.
        Returns the final response after following the redirect chain.
        Also populates redirect_chain on the response.
        """
        from urllib.parse import urljoin
        chain = []
        current_url = url
        current_method = method
        current_body = body

        # Mutable copy so we can accumulate Set-Cookie across hops
        current_headers: dict = dict(headers or {})
        # Cookie jar: name→value, seed from any Cookie header already set
        _cookies: dict = {}
        existing_cookie = current_headers.get("Cookie", "") or current_headers.get("cookie", "")
        for _pair in existing_cookie.split(";"):
            _pair = _pair.strip()
            if "=" in _pair:
                _k, _v = _pair.split("=", 1)
                _cookies[_k.strip()] = _v.strip()

        for _ in range(max_redirects):
            # Rebuild Cookie header from accumulated jar
            if _cookies:
                current_headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in _cookies.items())

            resp = self.request(current_method, current_url, headers=current_headers,
                                body=current_body)
            chain.append(current_url)

            # Absorb any Set-Cookie headers so subsequent hops stay authenticated.
            # set-cookie is stored as a list (multiple cookies per response).
            _sc_raw = resp.headers.get("set-cookie", [])
            if isinstance(_sc_raw, str):
                _sc_raw = [_sc_raw]
            for _cookie_hdr in _sc_raw:
                _first = _cookie_hdr.split(";")[0].strip()
                if "=" in _first:
                    _ck, _cv = _first.split("=", 1)
                    _cookies[_ck.strip()] = _cv.strip()

            if resp.error or resp.status not in (301, 302, 303, 307, 308):
                resp.redirect_chain = chain
                # Expose all cookies accumulated across the redirect chain
                # so callers (e.g. Session._merge_cookies) can see them.
                if _cookies:
                    existing_sc = resp.headers.get("set-cookie", [])
                    if isinstance(existing_sc, str):
                        existing_sc = [existing_sc]
                    merged = list(existing_sc)
                    for _ck, _cv in _cookies.items():
                        merged.append(f"{_ck}={_cv}; path=/")
                    resp.headers["set-cookie"] = merged
                return resp

            location = resp.header("location")
            if not location:
                resp.redirect_chain = chain
                return resp

            # Resolve relative redirects
            current_url = urljoin(current_url, location)

            # 303 always becomes GET; 301/302 become GET for non-GET/HEAD
            if resp.status == 303 or (resp.status in (301, 302) and
                                       current_method not in ("GET", "HEAD")):
                current_method = "GET"
                current_body = None

        # Max redirects hit — return last response
        resp.redirect_chain = chain
        return resp


    def get_tls_info(self, host: str, port: int = 443) -> dict:
        """
        Connect and extract TLS certificate and cipher info.
        Returns dict with cert details, cipher, protocol.
        """
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            if self._proxy_type and self._proxy_type.startswith("socks"):
                raw_sock = socket.create_connection(
                    (self._proxy_host, self._proxy_port), timeout=self.timeout)
                if self._proxy_type == "socks5":
                    _socks5_connect(raw_sock, host, port)
                else:
                    _socks4_connect(raw_sock, host, port)
            else:
                raw_sock = socket.create_connection((host, port), timeout=self.timeout)

            raw_sock.settimeout(self.timeout)
            sock = ctx.wrap_socket(raw_sock, server_hostname=host)

            cert = sock.getpeercert(binary_form=False) or {}
            cipher = sock.cipher()
            version = sock.version()

            sock.close()

            return {
                "subject": dict(x[0] for x in cert.get("subject", [])) if cert.get("subject") else {},
                "issuer": dict(x[0] for x in cert.get("issuer", [])) if cert.get("issuer") else {},
                "notBefore": cert.get("notBefore", ""),
                "notAfter": cert.get("notAfter", ""),
                "serialNumber": cert.get("serialNumber", ""),
                "cipher_name": cipher[0] if cipher else "",
                "cipher_version": cipher[1] if cipher else "",
                "cipher_bits": cipher[2] if cipher else 0,
                "tls_version": version or "",
                "error": None,
            }
        except Exception as e:
            return {"error": str(e)}
