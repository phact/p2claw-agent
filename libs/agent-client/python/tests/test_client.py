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
