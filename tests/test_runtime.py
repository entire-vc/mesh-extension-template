"""Exercise starter installation over HTTP, including forged reconfiguration."""

import importlib
import json
import logging
import socket
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest


@pytest.fixture
def starter(tmp_path, monkeypatch):
    root = Path(__file__).resolve().parents[1]
    monkeypatch.syspath_prepend(str(root))
    app = importlib.import_module("hello.app")
    monkeypatch.setattr(app, "SECRET_FILE", str(tmp_path / "state.json"))
    monkeypatch.delenv("HELLO_SIGNING_SECRET", raising=False)
    monkeypatch.delenv("MESH_JWKS_URL", raising=False)
    monkeypatch.delenv("HELLO_BOOTSTRAP_PEERS", raising=False)
    server = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    # Real handler threads and private state writes need scheduling headroom on
    # the shared runner; this suite tests authorization, not a five-second SLA.
    with httpx.Client(
        base_url=f"http://127.0.0.1:{server.server_port}", trust_env=False, timeout=30
    ) as client:
        yield app, client
    server.shutdown()
    thread.join(timeout=2)
    server.server_close()


def test_first_install_requires_trusted_peer_and_ignores_forwarded_headers(starter, monkeypatch):
    app, client = starter
    body = {"signing_secret": "synthetic-installation-key", "jwks_url": "https://trusted.test/jwks"}
    assert client.post("/mesh/install", json=body).status_code == 403
    monkeypatch.setenv("HELLO_BOOTSTRAP_PEERS", "192.0.2.10")
    response = client.post("/mesh/install", json=body, headers={"X-Forwarded-For": "192.0.2.10"})
    assert response.status_code == 403
    assert not Path(app.SECRET_FILE).exists()
    monkeypatch.setenv("HELLO_BOOTSTRAP_PEERS", "127.0.0.1")
    assert client.post("/mesh/install", json=body).status_code == 200
    assert app._load_state() == body


@pytest.mark.parametrize("replacement", [{}, {"signing_secret": "synthetic-installation-key"}])
def test_unsigned_jwks_replacement_is_refused_but_signed_request_works(starter, replacement):
    app, client = starter
    original = {"signing_secret": "synthetic-installation-key", "jwks_url": "https://trusted.test/jwks"}
    app._save_state(original)
    body = json.dumps(replacement | {"jwks_url": "https://replacement.test/jwks"}).encode()
    refused = client.post("/mesh/install", content=body)
    assert refused.status_code == 401
    assert app._load_state() == original
    stamp = str(int(time.time()))
    accepted = client.post(
        "/mesh/install",
        content=body,
        headers={
            "X-Mesh-Timestamp": stamp,
            "X-Mesh-Signature": app.sign(original["signing_secret"], stamp, body),
        },
    )
    assert accepted.status_code == 200
    assert app._load_state()["jwks_url"] == "https://replacement.test/jwks"


def test_installation_state_is_private(starter):
    app, _ = starter
    app._save_state({"signing_secret": "synthetic-installation-key"})
    assert Path(app.SECRET_FILE).stat().st_mode & 0o777 == 0o600


def test_health_and_events_require_valid_signature(starter):
    app, client = starter
    app._save_state({"signing_secret": "synthetic-installation-key"})
    assert client.get("/healthz").json() == {"status": "ok", "version": "0.1.0"}
    assert client.get("/mesh/ui/hello").status_code == 401
    body = json.dumps({"type": "task.updated"}).encode()
    assert client.post("/mesh/events", content=body).status_code == 401
    stamp = str(int(time.time()))
    headers = {"X-Mesh-Timestamp": stamp, "X-Mesh-Signature": app.sign("synthetic-installation-key", stamp, body)}
    accepted = client.post("/mesh/events", content=body, headers=headers)
    assert accepted.status_code == 200 and accepted.json()["ok"] is True


@pytest.mark.parametrize("payload", [[], "text", 1, None])
def test_signed_non_object_events_return_client_error(starter, payload):
    app, client = starter
    app._save_state({"signing_secret": "synthetic-installation-key"})
    body = json.dumps(payload).encode()
    stamp = str(int(time.time()))
    response = client.post(
        "/mesh/events", content=body,
        headers={"X-Mesh-Timestamp": stamp,
                 "X-Mesh-Signature": app.sign("synthetic-installation-key", stamp, body)},
    )
    assert response.status_code == 400
    assert response.json() == {"error": "event must be an object"}


def test_unsigned_event_header_cannot_override_signed_type(starter, caplog):
    app, client = starter
    app._save_state({"signing_secret": "synthetic-installation-key"})
    caplog.set_level(logging.INFO, logger=app.log.name)
    body = json.dumps({"type": "task.updated"}).encode()
    stamp = str(int(time.time()))
    headers = {
        "X-Mesh-Timestamp": stamp,
        "X-Mesh-Signature": app.sign("synthetic-installation-key", stamp, body),
    }
    assert client.post("/mesh/events", content=body, headers=headers).status_code == 200
    assert app.EVENTS[-1]["type"] == "task.updated"
    headers["X-Mesh-Event"] = "forged.event"
    assert client.post("/mesh/events", content=body, headers=headers).status_code == 200
    assert app.EVENTS[-1]["type"] == "task.updated"
    assert "forged.event" not in caplog.text


@pytest.mark.parametrize("event_type", [[], {}, 1, None])
def test_signed_non_string_event_types_return_client_error(starter, event_type):
    app, client = starter
    app._save_state({"signing_secret": "synthetic-installation-key"})
    body = json.dumps({"type": event_type}).encode()
    stamp = str(int(time.time()))
    response = client.post(
        "/mesh/events", content=body,
        headers={"X-Mesh-Timestamp": stamp,
                 "X-Mesh-Signature": app.sign("synthetic-installation-key", stamp, body)},
    )
    assert response.status_code == 400
    assert response.json() == {"error": "event type must be a string"}


@pytest.mark.parametrize("delivery", [r"forged\r\nlog-entry", "\x1b[31mforged-delivery\x1b[0m"])
def test_delivery_header_never_reaches_logs(starter, caplog, delivery):
    app, client = starter
    app._save_state({"signing_secret": "synthetic-installation-key"})
    caplog.set_level(logging.INFO, logger=app.log.name)
    body = b'{"type":"task.updated"}'
    stamp = str(int(time.time()))
    response = client.post("/mesh/events", content=body, headers={
        "X-Mesh-Timestamp": stamp,
        "X-Mesh-Signature": app.sign("synthetic-installation-key", stamp, body),
        "X-Mesh-Delivery": delivery,
    })
    assert response.status_code == 200
    assert "event" in caplog.text
    assert all(delivery not in record.getMessage() for record in caplog.records)


def test_request_logs_escape_controls_and_hide_query_and_headers(starter, caplog):
    app, client = starter
    caplog.set_level(logging.INFO, logger=app.log.name)
    with socket.create_connection(("127.0.0.1", client.base_url.port), timeout=5) as sock:
        sock.sendall(
            b"GET /missing-\x1b[31m?token=synthetic-query-value HTTP/1.1\r\n"
            b"Host: untrusted-host\r\nUser-Agent: untrusted-user-agent\r\n\r\n"
        )
        assert b"404" in sock.recv(4096)
    assert "missing-" in caplog.text
    for value in ("\x1b", "synthetic-query-value", "untrusted-host", "untrusted-user-agent"):
        assert all(value not in record.getMessage() for record in caplog.records)


def test_payload_and_jwt_error_values_never_reach_logs(starter, monkeypatch, caplog):
    app, client = starter
    caplog.set_level(logging.INFO, logger=app.log.name)
    monkeypatch.setenv("HELLO_BOOTSTRAP_PEERS", "127.0.0.1")
    secret = "synthetic-installation-key"
    assert client.post("/mesh/install", json={
        "signing_secret": secret, "jwks_url": "https://trusted.test/jwks",
        "workspace_id": "forged-workspace\r\n\x1b[31m",
    }).status_code == 200
    body = json.dumps({"type": "forged-type\r\n\x1b[31m"}).encode()
    stamp = str(int(time.time()))
    assert client.post("/mesh/events", content=body, headers={
        "X-Mesh-Timestamp": stamp, "X-Mesh-Signature": app.sign(secret, stamp, body),
    }).status_code == 200
    def reject_token(token):
        raise ValueError("forged-jwt-error\r\n\x1b[31m")
    monkeypatch.setattr(app, "verify_jwt", reject_token)
    assert client.get("/mesh/ui/hello", headers={"Authorization": "Bearer synthetic"}).status_code == 401
    assert "installed" in caplog.text and "event" in caplog.text and "jwt rejected" in caplog.text
    for value in ("forged-workspace", "forged-type", "forged-jwt-error", "\x1b"):
        assert all(value not in record.getMessage() for record in caplog.records)
