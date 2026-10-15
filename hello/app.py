"""Minimal external Mesh extension: install, events, healthz, two UI screens."""
import hashlib
import hmac
import html
import json
import re
import logging
import os
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

import jwt

from . import __version__

log = logging.getLogger("hello")

MAX_BODY = 1 << 20
MAX_SKEW = 300
SECRET_FILE = os.environ.get("HELLO_STATE_FILE", "/tmp/hello-state.json")
_lock = threading.Lock()
EVENTS = []  # last 50 events, newest last


def _load_state():
    try:
        with open(SECRET_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _save_state(state):
    # A new private inode avoids permissive inherited modes and partial writes.
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", dir=Path(SECRET_FILE).parent, delete=False) as f:
            temporary = f.name
            json.dump(state, f)
        os.replace(temporary, SECRET_FILE)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)


def signing_secret():
    return os.environ.get("HELLO_SIGNING_SECRET") or _load_state().get("signing_secret", "")


def jwks_url():
    return os.environ.get("MESH_JWKS_URL") or _load_state().get("jwks_url", "")


def sign(secret, timestamp, body):
    """Mesh signs `{timestamp}.{body}` with HMAC-SHA256, hex-encoded."""
    mac = hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256)
    return mac.hexdigest()


def verify_signature(secret, timestamp, signature, body, now=None):
    if not secret or not timestamp or not signature:
        return False
    try:
        skew = abs((now if now is not None else time.time()) - int(timestamp))
    except ValueError:
        return False
    if skew > MAX_SKEW:
        return False
    return hmac.compare_digest(sign(secret, timestamp, body), signature)


def verify_jwt(token):
    """Validate a Mesh-issued UI token against the instance JWKS; returns claims."""
    url = jwks_url()
    if not url:
        raise ValueError("jwks url is not configured")
    key = jwt.PyJWKClient(url, cache_keys=True).get_signing_key_from_jwt(token).key
    return jwt.decode(
        token,
        key,
        algorithms=["RS256", "ES256", "EdDSA"],
        audience=os.environ.get("HELLO_JWT_AUDIENCE", "example"),
        options={"require": ["exp"]},
    )


PAGE = """<!doctype html><meta charset="utf-8"><title>{title}</title>
<body style="font-family:system-ui;margin:2rem">{body}</body>"""

HELLO_BODY = """<h1>Hello, {email}</h1>
<button id="b">Say hello</button>
<script>
document.getElementById('b').onclick = function () {{
  parent.postMessage({{type: 'mesh.toast', level: 'info', message: 'Hello from mesh-ext-hello {version}'}}, '*');
}};
</script>"""


def _redact(line):
    """Drop the query string from a request line."""
    return re.sub(r"\?\S*", "?[redacted]", line)


class Handler(BaseHTTPRequestHandler):
    server_version = "mesh-ext-hello/" + __version__

    def log_message(self, fmt, *args):
        # the query string may carry a ?token= JWT, so it never reaches the log
        log.info("%s %r", self.address_string(), _redact(fmt % args))

    def _send(self, code, body=b"", ctype="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "frame-ancestors " + os.environ.get("MESH_ORIGIN", "*"))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            n = -1
        if n < 0 or n > MAX_BODY:
            self._send(413, {"error": "bad body size"})
            return None
        return self.rfile.read(n)

    def _claims(self, query):
        auth = self.headers.get("Authorization", "")
        token = auth[7:] if auth.startswith("Bearer ") else ""
        if not token:
            token = (query.get("token") or [""])[0] if isinstance(query, dict) else ""
        try:
            return verify_jwt(token)
        except Exception:  # any failure means unauthenticated
            log.warning("jwt rejected")
            return None

    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/healthz":
            return self._send(200, {"status": "ok", "version": __version__})
        if url.path in ("/mesh/ui/hello", "/mesh/ui/task"):
            from urllib.parse import parse_qs

            claims = self._claims(parse_qs(url.query))
            if claims is None:
                return self._send(401, {"error": "invalid token"})
            email = html.escape(str(claims.get("email", claims.get("sub", "anonymous"))))
            if url.path == "/mesh/ui/hello":
                body = HELLO_BODY.format(email=email, version=__version__)
            else:
                with _lock:
                    last = EVENTS[-1]["type"] if EVENTS else "none yet"
                body = "<h2>Hello panel</h2><p>%s, task %s</p><p>Last event: %s</p>" % (
                    email,
                    html.escape(str(claims.get("task_id", "?"))),
                    html.escape(last),
                )
            return self._send(200, PAGE.format(title="Hello", body=body), "text/html; charset=utf-8")
        if url.path == "/mesh/debug/events":
            if os.environ.get("HELLO_DEBUG") != "1":
                return self._send(404, {"error": "not found"})
            with _lock:
                return self._send(200, EVENTS)
        self._send(404, {"error": "not found"})

    def do_HEAD(self):
        if urlparse(self.path).path == "/healthz":
            return self._send(200, b"")
        self._send(404, b"")

    def do_POST(self):
        path = urlparse(self.path).path
        body = self._read_body()
        if body is None:
            return
        if path == "/mesh/install":
            return self._install(body)
        if path == "/mesh/events":
            return self._events(body)
        self._send(404, {"error": "not found"})

    def _install(self, body):
        try:
            data = json.loads(body or b"{}")
        except ValueError:
            return self._send(400, {"error": "invalid json"})
        if not isinstance(data, dict):
            return self._send(400, {"error": "invalid installation"})
        secret = data.get("signing_secret") or data.get("secret") or ""
        keys = data.get("jwks_url", "")
        if not isinstance(secret, str) or (secret and not 16 <= len(secret) <= 4096):
            return self._send(400, {"error": "invalid installation"})
        if not isinstance(keys, str) or (keys and not keys.startswith("https://")):
            return self._send(400, {"error": "invalid installation"})
        with _lock:
            existing = signing_secret()
            if existing:
                # Every reconfiguration, including a JWKS-only update, is signed.
                ts = self.headers.get("X-Mesh-Timestamp", "")
                if not verify_signature(existing, ts, self.headers.get("X-Mesh-Signature", ""), body):
                    return self._send(401, {"error": "bad signature"})
            else:
                # Trust only a direct peer explicitly provisioned by the operator.
                # Forwarded headers never authenticate a bootstrap request.
                peers = {p.strip() for p in os.environ.get("HELLO_BOOTSTRAP_PEERS", "").split(",") if p.strip()}
                if self.client_address[0] not in peers:
                    return self._send(403, {"error": "bootstrap peer not trusted"})
                if not secret or not keys:
                    return self._send(400, {"error": "installation keys required"})
            state = _load_state()
            if secret:
                state["signing_secret"] = secret
            if data.get("jwks_url"):
                state["jwks_url"] = data["jwks_url"]
            try:
                _save_state(state)
            except OSError:
                return self._send(503, {"error": "installation state unavailable"})
        log.info("installed version=%s", __version__)
        self._send(200, {"ok": True, "version": __version__})

    def _events(self, body):
        ok = verify_signature(
            signing_secret(),
            self.headers.get("X-Mesh-Timestamp", ""),
            self.headers.get("X-Mesh-Signature", ""),
            body,
        )
        if not ok:
            return self._send(401, {"error": "bad signature"})
        try:
            event = json.loads(body)
        except ValueError:
            return self._send(400, {"error": "invalid json"})
        if not isinstance(event, dict):
            return self._send(400, {"error": "event must be an object"})
        # The signature authenticates the body, not transport headers.
        etype = event.get("type", "unknown")
        if not isinstance(etype, str):
            return self._send(400, {"error": "event type must be a string"})
        log.info("event received")
        with _lock:
            EVENTS.append({"type": etype, "at": time.time()})
            del EVENTS[:-50]
        self._send(200, {"ok": True})


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    port = int(os.environ.get("PORT", "8080"))
    log.info("mesh-ext-hello %s listening on :%d", __version__, port)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
