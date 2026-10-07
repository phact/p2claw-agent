from __future__ import annotations

import json
import os
import socketserver
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler
from typing import Any

import pytest

from p2claw_agent_client import AgentClient, AgentError, AgentNotRunning, default_socket_path


class FakeAgent:
    """Unix-socket HTTP server that records requests and replays canned
    responses keyed by (method, path)."""

    def __init__(self, path: str):
        self.path = path
        self.requests: list[dict[str, Any]] = []
        self.responses: dict[tuple[str, str], tuple[int, Any]] = {}
        agent = self

        class Handler(BaseHTTPRequestHandler):
            def _handle(self) -> None:
                n = int(self.headers.get("content-length") or 0)
                body = self.rfile.read(n) if n else b""
                agent.requests.append(
                    {
                        "method": self.command,
                        "path": self.path,
                        "headers": dict(self.headers),
                        "body": body,
                    }
                )
                key = (self.command, self.path.split("?")[0])
                status, payload = agent.responses.get(key, (404, {"error": "not_found"}))
                raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            do_GET = do_POST = do_PUT = do_DELETE = _handle

            def log_message(self, *a: object) -> None:
                pass

            def address_string(self) -> str:
                return "uds"

        class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
            daemon_threads = True

            def get_request(self):  # type: ignore[no-untyped-def]
                req, _ = super().get_request()
                return req, ("uds", 0)

        self.server = Server(path, Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def agent(tmp_path: Any) -> Iterator[FakeAgent]:
    a = FakeAgent(str(tmp_path / "agent.sock"))
    yield a
    a.close()


def client(agent: FakeAgent) -> AgentClient:
    return AgentClient(socket_path=agent.path)


def test_status_and_identity(agent: FakeAgent) -> None:
    agent.responses[("GET", "/v1/identity")] = (
        200,
        {"peer_id": "p", "alias": "a-b-1", "registered": True},
    )
    agent.responses[("GET", "/v1/status")] = (200, {"version": "0.10.19", "route_count": 2})
    c = client(agent)
    assert c.identity()["alias"] == "a-b-1"
    assert c.status()["route_count"] == 2


def test_errors_carry_the_agent_error_code(agent: FakeAgent) -> None:
    agent.responses[("POST", "/v1/routes")] = (400, {"error": "bad_name", "detail": "too long"})
    with pytest.raises(AgentError) as e:
        client(agent).expose("x" * 40, port=1)
    assert (e.value.status, e.value.error, e.value.detail) == (400, "bad_name", "too long")


def test_app_returns_none_for_unknown(agent: FakeAgent) -> None:
    assert client(agent).app("nope") is None


def test_expose_bodies(agent: FakeAgent, tmp_path: Any) -> None:
    agent.responses[("POST", "/v1/routes")] = (200, {"name": "x", "url": None})
    c = client(agent)

    c.expose("web", port=5173)
    c.expose("svc", socket_path=str(tmp_path / "svc.sock"))
    c.expose("gated", port=8000, auth_oauth=["github"])
    c.expose("flip", port=8000, private=False)

    bodies = [json.loads(r["body"]) for r in agent.requests]
    assert bodies[0] == {"name": "web", "upstream": "http://127.0.0.1:5173"}
    assert bodies[1] == {
        "name": "svc",
        "upstream": f"unix:{tmp_path / 'svc.sock'}",
        "visibility": "private",
    }
    assert bodies[2]["auth"] == [{"kind": "oauth", "providers": ["github"]}]
    assert bodies[3]["visibility"] == "public"


def test_expose_rejects_bad_combinations(agent: FakeAgent) -> None:
    c = client(agent)
    with pytest.raises(ValueError):
        c.expose("x")
    with pytest.raises(ValueError):
        c.expose("x", port=1, socket_path="/s")
    with pytest.raises(ValueError):
        c.expose("x", socket_path="/s", private=False)
    with pytest.raises(ValueError):
        c.expose("x", port=1, private=True, auth_oauth=True)
    with pytest.raises(ValueError):
        c.expose("x", socket_path="/tmp/has space.sock")
    assert agent.requests == []


def test_share_merges_and_unshare_removes(agent: FakeAgent) -> None:
    table = {"shares": [{"app": "svc", "peers": ["p1"]}, {"app": "other", "peers": ["p9"]}]}
    agent.responses[("GET", "/v1/shares")] = (200, table)
    agent.responses[("PUT", "/v1/shares")] = (
        200,
        {"shares": [{"app": "svc", "peers": ["p1", "p2"]}, {"app": "other", "peers": ["p9"]}]},
    )
    c = client(agent)

    assert c.share("svc", ["p1", "p2"]) == ["p1", "p2"]
    put = json.loads(agent.requests[-1]["body"])
    assert put == {
        "shares": [{"app": "svc", "peers": ["p1", "p2"]}, {"app": "other", "peers": ["p9"]}]
    }

    c.unshare("svc", "p1")
    assert json.loads(agent.requests[-1]["body"])["shares"][0] == {"app": "svc", "peers": []}

    c.unshare("svc")
    assert json.loads(agent.requests[-1]["body"]) == {"shares": [{"app": "other", "peers": ["p9"]}]}


def test_email_settings_and_allowlist(agent: FakeAgent) -> None:
    summary = {
        "enabled": False,
        "addresses": [],
        "allowlist": ["you@gmail.com"],
        "unread": 0,
        "rejections": None,
        "rejections_available": False,
    }
    agent.responses[("GET", "/v1/email")] = (200, summary)
    agent.responses[("PUT", "/v1/email")] = (200, {**summary, "enabled": True})
    agent.responses[("PUT", "/v1/email/allowlist")] = (
        200,
        {"allowlist": ["you@gmail.com", "b@x.org"]},
    )
    c = client(agent)

    assert c.email()["rejections"] is None
    assert c.email_enable()["enabled"] is True
    assert json.loads(agent.requests[-1]["body"]) == {"enabled": True}
    c.email_disable()
    assert json.loads(agent.requests[-1]["body"]) == {"enabled": False}

    assert c.email_allow(["You+tag@Gmail.com", "B@x.org"]) == ["you@gmail.com", "b@x.org"]
    assert json.loads(agent.requests[-1]["body"]) == {"allowlist": ["you@gmail.com", "b@x.org"]}
    c.email_disallow("you+other@gmail.com")
    assert json.loads(agent.requests[-1]["body"]) == {"allowlist": []}
    with pytest.raises(ValueError):
        c.email_allow(["nope"])


def test_email_messages(agent: FakeAgent) -> None:
    light = {"id": "m_1", "kind": "message", "subject": "hi", "acked": False}
    agent.responses[("GET", "/v1/email/messages")] = (200, {"messages": [light]})
    agent.responses[("GET", "/v1/email/messages/m_1")] = (200, {**light, "text": "body"})
    agent.responses[("GET", "/v1/email/messages/m_1/attachments/a_1")] = (200, b"%PDF-1.4")
    agent.responses[("POST", "/v1/email/messages/m_1/ack")] = (200, {**light, "acked": True})
    agent.responses[("DELETE", "/v1/email/messages/m_1")] = (204, b"")
    agent.responses[("GET", "/v1/email/rejected")] = (
        200,
        {"totals": {"not_allowed": 2}, "recent": [], "admitted_today": 1, "daily_limit": 1000},
    )
    c = client(agent)

    assert c.email_messages() == [light]
    assert c.email_messages(unread=True) == [light]
    assert agent.requests[-1]["path"] == "/v1/email/messages?unread=1"
    assert c.email_message("m_1")["text"] == "body"
    # The fake answers the raw form with the same JSON; the client must
    # hand it back as bytes untouched.
    assert c.email_message("m_1", raw=True) == json.dumps({**light, "text": "body"}).encode()
    assert agent.requests[-1]["path"] == "/v1/email/messages/m_1?format=raw"
    assert c.email_attachment("m_1", "a_1") == b"%PDF-1.4"
    assert c.email_ack("m_1")["acked"] is True
    assert c.email_delete("m_1") is None
    assert agent.requests[-1]["method"] == "DELETE"
    assert c.email_rejected()["totals"] == {"not_allowed": 2}
    with pytest.raises(AgentError) as e:
        c.email_attachment("m_1", "a_9")
    assert e.value.status == 404


def test_email_watch_yields_ids(agent: FakeAgent) -> None:
    agent.responses[("GET", "/v1/email/messages")] = (
        200,
        b'{"id":"m_1"}\n{"lagged":3}\n{"id":"m_2"}\n',
    )
    assert list(client(agent).email_watch()) == ["m_1", "m_2"]
    assert agent.requests[-1]["path"] == "/v1/email/messages?watch=1"


def test_fetch_targets_the_proxy_and_returns_app_errors(agent: FakeAgent) -> None:
    agent.responses[("POST", "/v1/proxy/blue-otter-7392/svc/items")] = (201, {"ok": True})
    agent.responses[("GET", "/v1/proxy/blue-otter-7392/svc/missing")] = (
        404,
        {"error": "not_found"},
    )
    c = client(agent)

    r = c.fetch("blue-otter-7392", "svc", "items?x=1", method="POST", json_body={"a": 1})
    assert r.status == 201 and r.json() == {"ok": True}
    sent = agent.requests[-1]
    assert sent["path"] == "/v1/proxy/blue-otter-7392/svc/items?x=1"
    assert json.loads(sent["body"]) == {"a": 1}
    assert sent["headers"]["content-type"] == "application/json"

    assert c.fetch("blue-otter-7392", "svc", "/missing").status == 404


def test_fetch_stream(agent: FakeAgent) -> None:
    agent.responses[("GET", "/v1/proxy/p/svc/big")] = (200, b"x" * 200_000)
    with client(agent).fetch("p", "svc", "/big", stream=True) as r:
        assert r.status == 200
        assert sum(len(c) for c in r.iter_chunks()) == 200_000


def test_agent_not_running(tmp_path: Any) -> None:
    with pytest.raises(AgentNotRunning):
        AgentClient(socket_path=str(tmp_path / "missing.sock")).status()


def test_default_socket_path_follows_the_agent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("P2CLAW_AGENT_RUNTIME_DIR", "/srv/p2claw")
    assert default_socket_path() == "/srv/p2claw/agent.sock"
    monkeypatch.delenv("P2CLAW_AGENT_RUNTIME_DIR")
    monkeypatch.setattr("sys.platform", "darwin")
    assert default_socket_path() == f"/tmp/p2claw-{os.geteuid()}/agent.sock"
    monkeypatch.setattr("sys.platform", "linux")
    monkeypatch.setenv("XDG_RUNTIME_DIR", "/run/user/1000")
    assert default_socket_path() == "/run/user/1000/p2claw/agent.sock"


def test_websocket_through_the_proxy_path(tmp_path: Any) -> None:
    sync_server = pytest.importorskip("websockets.sync.server")
    sock = str(tmp_path / "ws.sock")
    seen: list[str] = []

    def echo(ws: Any) -> None:
        seen.append(ws.request.path)
        for msg in ws:
            ws.send(msg)

    with sync_server.unix_serve(echo, sock) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        with AgentClient(socket_path=sock).websocket("blue-otter-7392", "svc", "/ws") as ws:
            ws.send("hi")
            assert ws.recv() == "hi"
        server.shutdown()
    assert seen == ["/v1/proxy/blue-otter-7392/svc/ws"]


def _b64url_sha256(data: bytes) -> str:
    import base64
    import hashlib

    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


def _state_for(nonce_hash: str) -> str:
    import base64

    claims = json.dumps({"peer_id": "p", "flow_id": "f_1", "nonce_hash": nonce_hash}).encode()
    return "s1." + base64.urlsafe_b64encode(claims).rstrip(b"=").decode() + ".sig"


def test_oauth_grants_calls(agent: FakeAgent) -> None:
    agent.responses[("GET", "/v1/oauth-grants/providers")] = (
        200,
        {"providers": [{"name": "google", "scopes": ["calendar.app.created"], "revoke_url": "r"}]},
    )
    agent.responses[("POST", "/v1/oauth-grants/flows")] = (
        200,
        {"flow_id": "f_1", "authorize_url": "https://accounts.google.com/x"},
    )
    agent.responses[("GET", "/v1/oauth-grants/flows/f_1")] = (
        200,
        {"flow_id": "f_1", "status": "ready", "code": "c0de", "state": "s1.x.y"},
    )
    agent.responses[("POST", "/v1/oauth-grants/flows/f_1/exchange")] = (
        200,
        {"access_token": "at", "expires_in": 3600, "provider": "google", "grant": "g1.k.z"},
    )
    agent.responses[("POST", "/v1/oauth-grants/refresh")] = (
        200,
        {"access_token": "at2", "expires_in": 3600},
    )
    agent.responses[("GET", "/v1/oauth-grants")] = (
        200,
        {"grants": [{"id": "gr_1", "provider": "google", "scopes": [], "created_at": 1}]},
    )
    agent.responses[("GET", "/v1/oauth-grants/gr_1/token")] = (
        200,
        {"access_token": "at3", "expires_in": 100},
    )
    agent.responses[("DELETE", "/v1/oauth-grants/gr_1")] = (
        200,
        {"id": "gr_1", "provider": "google", "provider_revoked": True},
    )
    c = client(agent)

    assert c.oauth_grants_providers()[0]["name"] == "google"
    started = c.oauth_grants_start("google", ["calendar.app.created"], "chal", "nh")
    assert started["flow_id"] == "f_1"
    assert json.loads(agent.requests[-1]["body"]) == {
        "provider": "google",
        "scopes": ["calendar.app.created"],
        "code_challenge": "chal",
        "nonce_hash": "nh",
    }
    assert c.oauth_grants_wait("f_1")["code"] == "c0de"
    assert agent.requests[-1]["path"] == "/v1/oauth-grants/flows/f_1?wait=1"
    assert c.oauth_grants_exchange("f_1", "verifier")["grant"] == "g1.k.z"
    assert json.loads(agent.requests[-1]["body"]) == {"code_verifier": "verifier", "store": False}
    c.oauth_grants_exchange("f_1", "verifier", store=True)
    assert json.loads(agent.requests[-1]["body"])["store"] is True
    assert c.oauth_grants_refresh("g1.k.z", "google")["access_token"] == "at2"
    assert json.loads(agent.requests[-1]["body"]) == {"provider": "google", "grant": "g1.k.z"}
    assert c.oauth_grants()[0]["id"] == "gr_1"
    assert c.oauth_grants_token("gr_1")["access_token"] == "at3"
    assert c.oauth_grants_revoke("gr_1")["provider_revoked"] is True
    assert agent.requests[-1]["method"] == "DELETE"

    agent.responses[("GET", "/v1/oauth-grants/gr_1/token")] = (410, {"error": "invalid_grant"})
    with pytest.raises(AgentError) as e:
        c.oauth_grants_token("gr_1")
    assert (e.value.status, e.value.error) == (410, "invalid_grant")


def test_oauth_grants_wait_honours_timeout(agent: FakeAgent) -> None:
    agent.responses[("GET", "/v1/oauth-grants/flows/f_1")] = (
        200,
        {"flow_id": "f_1", "status": "pending"},
    )
    view = client(agent).oauth_grants_wait("f_1", timeout=0.2)
    assert view["status"] == "pending"
    assert "wait=1&timeout=1" in agent.requests[0]["path"]


def test_oauth_grants_connect_runs_the_app_side(agent: FakeAgent) -> None:
    agent.responses[("POST", "/v1/oauth-grants/flows")] = (
        200,
        {"flow_id": "f_1", "authorize_url": "https://accounts.google.com/x"},
    )
    agent.responses[("POST", "/v1/oauth-grants/flows/f_1/exchange")] = (
        200,
        {"access_token": "at", "expires_in": 3600, "provider": "google", "grant_id": "gr_1"},
    )
    c = client(agent)
    flow = c.oauth_grants_connect("google", ["calendar.app.created"], store=True)
    assert (flow.flow_id, flow.authorize_url) == ("f_1", "https://accounts.google.com/x")
    start = json.loads(agent.requests[-1]["body"])
    assert len(start["code_challenge"]) == 43 and len(start["nonce_hash"]) == 43

    # The callback carries this flow's nonce hash in its state.
    agent.responses[("GET", "/v1/oauth-grants/flows/f_1")] = (
        200,
        {
            "flow_id": "f_1",
            "status": "ready",
            "code": "c0de",
            "state": _state_for(start["nonce_hash"]),
        },
    )
    result = flow.wait()
    assert result["grant_id"] == "gr_1"
    exchange = json.loads(agent.requests[-1]["body"])
    assert exchange["store"] is True
    assert _b64url_sha256(exchange["code_verifier"].encode()) == start["code_challenge"]


def test_oauth_grants_connect_rejects_foreign_callbacks_and_failures(agent: FakeAgent) -> None:
    agent.responses[("POST", "/v1/oauth-grants/flows")] = (
        200,
        {"flow_id": "f_1", "authorize_url": "u"},
    )
    c = client(agent)
    flow = c.oauth_grants_connect("google", ["s"])
    agent.responses[("GET", "/v1/oauth-grants/flows/f_1")] = (
        200,
        {"flow_id": "f_1", "status": "ready", "code": "c0de", "state": _state_for("other")},
    )
    with pytest.raises(AgentError) as e:
        flow.wait()
    assert e.value.error == "state_mismatch"
    assert not any("exchange" in r["path"] for r in agent.requests)

    agent.responses[("GET", "/v1/oauth-grants/flows/f_1")] = (
        200,
        {"flow_id": "f_1", "status": "error", "error": "access_denied"},
    )
    with pytest.raises(AgentError) as e:
        flow.wait()
    assert (e.value.error, e.value.detail) == ("flow_error", "access_denied")

    agent.responses[("GET", "/v1/oauth-grants/flows/f_1")] = (
        200,
        {"flow_id": "f_1", "status": "pending"},
    )
    with pytest.raises(TimeoutError):
        flow.wait(timeout=0.1)
