#!/usr/bin/env python3
"""Minimal stdlib-only HTTP client with a requests-like interface.

Exists so the whole toolkit runs on a bare Python install with NO pip packages
and NO internet access. `requests` is not guaranteed to be present on a field
machine and cannot be installed offline.

Supports only what this project needs: GET/POST/PUT/DELETE, basic auth, JSON
bodies, cookies (for Security Onion's Kratos login), multipart file upload
(for Kibana's saved-object import), and optional TLS verification.
"""
import base64
import http.cookiejar
import json as _json
import ssl
import urllib.error
import urllib.parse
import urllib.request
import uuid


class Response:
    """Mimics the small slice of requests.Response that this project uses."""

    def __init__(self, status_code, body, headers, url):
        self.status_code = status_code
        self.content = body
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self.url = url

    @property
    def text(self):
        try:
            return self.content.decode("utf-8", errors="replace")
        except Exception:
            return str(self.content)

    def json(self):
        return _json.loads(self.text)

    def raise_for_status(self):
        if not (200 <= self.status_code < 300):
            raise RuntimeError(f"HTTP {self.status_code} for {self.url}: {self.text[:300]}")


def _encode_multipart(fields, files):
    """Build a multipart/form-data body. files: {name: (filename, bytes, ctype)}"""
    boundary = uuid.uuid4().hex
    out = []
    for name, value in (fields or {}).items():
        out.append(f"--{boundary}\r\n".encode())
        out.append(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode())
        out.append(f"{value}\r\n".encode())
    for name, (filename, data, ctype) in (files or {}).items():
        if isinstance(data, str):
            data = data.encode("utf-8")
        out.append(f"--{boundary}\r\n".encode())
        out.append(
            f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'.encode()
        )
        out.append(f"Content-Type: {ctype}\r\n\r\n".encode())
        out.append(data)
        out.append(b"\r\n")
    out.append(f"--{boundary}--\r\n".encode())
    return b"".join(out), f"multipart/form-data; boundary={boundary}"


class Session:
    """requests.Session work-alike, stdlib only."""

    def __init__(self, verify=True):
        self.verify = verify
        self.cookiejar = http.cookiejar.CookieJar()
        self._build_opener()

    def _build_opener(self):
        if self.verify is False:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        elif isinstance(self.verify, str):
            ctx = ssl.create_default_context(cafile=self.verify)
        else:
            ctx = ssl.create_default_context()
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx),
            urllib.request.HTTPCookieProcessor(self.cookiejar),
            _NoRedirect(),
        )

    # cookie access used to confirm the Kratos session came back
    @property
    def cookies(self):
        return {c.name: c.value for c in self.cookiejar}

    def request(self, method, url, auth=None, json=None, data=None, params=None,
                headers=None, files=None, timeout=120, allow_redirects=True, **_):
        if self.verify is not getattr(self, "_verify_applied", object()):
            self._build_opener()
            self._verify_applied = self.verify

        if params:
            flat = []
            for k, v in params.items():
                if isinstance(v, (list, tuple)):
                    flat.extend((k, str(x)) for x in v)
                else:
                    flat.append((k, str(v)))
            url = url + ("&" if "?" in url else "?") + urllib.parse.urlencode(flat)

        hdrs = dict(headers or {})
        body = None
        if files is not None:
            fixed = {}
            for name, spec in files.items():
                fname, fobj, ctype = (list(spec) + ["application/octet-stream"])[:3]
                fixed[name] = (fname, fobj.read() if hasattr(fobj, "read") else fobj, ctype)
            body, ctype = _encode_multipart(data if isinstance(data, dict) else None, fixed)
            hdrs["Content-Type"] = ctype
        elif json is not None:
            body = _json.dumps(json).encode("utf-8")
            hdrs.setdefault("Content-Type", "application/json")
        elif data is not None:
            body = data.encode("utf-8") if isinstance(data, str) else data

        if auth:
            token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
            hdrs["Authorization"] = f"Basic {token}"

        req = urllib.request.Request(url, data=body, headers=hdrs, method=method.upper())
        try:
            with self._opener.open(req, timeout=timeout) as r:
                return Response(r.status, r.read(), dict(r.headers), url)
        except urllib.error.HTTPError as e:
            return Response(e.code, e.read(), dict(e.headers or {}), url)
        except urllib.error.URLError as e:
            raise ConnectionError(f"cannot reach {url}: {e.reason}") from e

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def post(self, url, **kw):
        return self.request("POST", url, **kw)

    def put(self, url, **kw):
        return self.request("PUT", url, **kw)

    def delete(self, url, **kw):
        return self.request("DELETE", url, **kw)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Follow redirects like a browser (Kratos login depends on it)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def disable_warnings(*_a, **_k):
    """No-op: stdlib does not emit urllib3's InsecureRequestWarning."""
