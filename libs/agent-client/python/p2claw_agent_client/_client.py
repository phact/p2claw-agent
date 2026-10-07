"""Client for the p2claw agent's local API (HTTP over a Unix socket)."""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import secrets
import socket
import sys
import time
from collections.abc import Iterable, Iterator, Mapping
from typing import Any

__all__ = [
    "AgentClient",
    "AgentError",
    "AgentNotRunning",
    "OauthGrantFlow",
    "Response",
    "StreamingResponse",
    "default_socket_path",
]

Json = Any

# Sentinel for "use the client's default timeout".
_DEFAULT_TIMEOUT = -1.0

# Longest the agent holds a `?wait=1` poll before answering `pending`;
# the request timeout must outlast it.
_WAIT_POLL_SECONDS = 55

# Characters a URL would percent-encode; the agent reads a `unix:`
# upstream path back verbatim, so they can't appear in a socket path.
_UNSAFE_SOCKET_CHARS = set('%?#"<>`{}^|\\')


def default_socket_path() -> str:
    """The socket the agent listens on, resolved the way the agent does."""
    override = os.environ.get("P2CLAW_AGENT_RUNTIME_DIR")
    if override:
        return os.path.join(override, "agent.sock")
    if sys.platform.startswith("linux"):
        xdg = os.environ.get("XDG_RUNTIME_DIR")
        if xdg:
            return os.path.join(xdg, "p2claw", "agent.sock")
        if os.geteuid() == 0 and os.path.isdir("/run/p2claw"):
            return "/run/p2claw/agent.sock"
    return f"/tmp/p2claw-{os.geteuid()}/agent.sock"


class AgentError(Exception):
    """The agent answered a management call with an error."""

    def __init__(self, status: int, error: str, detail: str | None = None, body: Json = None):
        self.status = status
        self.error = error
        self.detail = detail
        self.body = body
        super().__init__(f"{status} {error}" + (f": {detail}" if detail else ""))


class AgentNotRunning(AgentError):
    """Nothing is listening on the agent socket."""

    def __init__(self, path: str, cause: OSError):
        super().__init__(0, "agent_not_running", f"{path}: {cause}")
        self.path = path


class _UnixConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float | None):
        super().__init__("localhost", timeout=timeout)
        self._path = path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        if self.timeout is not None:
            sock.settimeout(self.timeout)
        try:
            sock.connect(self._path)
        except OSError as e:
            sock.close()
            raise AgentNotRunning(self._path, e) from e
        self.sock = sock


class Response:
    """A fully read response from an app on another machine."""

    def __init__(self, status: int, reason: str, headers: list[tuple[str, str]], body: bytes):
        self.status = status
        self.reason = reason
        self.headers = headers
        self.body = body

    def header(self, name: str) -> str | None:
        name = name.lower()
        return next((v for k, v in self.headers if k.lower() == name), None)

    def text(self, encoding: str = "utf-8") -> str:
        return self.body.decode(encoding)

    def json(self) -> Json:
        return json.loads(self.body)

    def __repr__(self) -> str:
        return f"<Response {self.status} {len(self.body)} bytes>"


class StreamingResponse:
    """A response whose body is read incrementally. Close it when done."""

    def __init__(self, conn: _UnixConnection, resp: http.client.HTTPResponse):
        self._conn = conn
        self._resp = resp
        self.status = resp.status
        self.reason = resp.reason
        self.headers = resp.getheaders()

    def header(self, name: str) -> str | None:
        return self._resp.getheader(name)

    def read(self, n: int = -1) -> bytes:
        return self._resp.read(n)

    def iter_chunks(self, size: int = 64 * 1024) -> Iterable[bytes]:
        while chunk := self._resp.read1(size):
            yield chunk

    def close(self) -> None:
        self._resp.close()
        self._conn.close()

    def __enter__(self) -> StreamingResponse:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class AgentClient:
    """Talks to the p2claw agent on this machine.

    Management calls (`status`, `apps`, `expose`, `share`, ...) raise
    :class:`AgentError` on failure. :meth:`fetch` returns whatever the
    app on the other machine answered, including error statuses.
    """

    def __init__(self, socket_path: str | None = None, timeout: float | None = 30.0):
        self.socket_path = socket_path or default_socket_path()
        self.timeout = timeout

    # -- transport -------------------------------------------------------

    def _open(
        self,
        method: str,
        path: str,
        headers: Mapping[str, str] | None,
        body: bytes | None,
        timeout: float | None,
    ) -> tuple[_UnixConnection, http.client.HTTPResponse]:
        conn = _UnixConnection(self.socket_path, timeout)
        try:
            conn.request(method, path, body=body, headers=dict(headers or {}))
            return conn, conn.getresponse()
        except BaseException:
            conn.close()
            raise

    def _call(
        self,
        method: str,
        path: str,
        payload: Json = None,
        timeout: float | None = _DEFAULT_TIMEOUT,
    ) -> Json:
        body = None if payload is None else json.dumps(payload).encode()
        headers = {"content-type": "application/json"} if body is not None else {}
        if timeout == _DEFAULT_TIMEOUT:
            timeout = self.timeout
        conn, resp = self._open(method, path, headers, body, timeout)
        try:
            raw = resp.read()
        finally:
            conn.close()
        parsed: Json = None
        if raw:
            try:
                parsed = json.loads(raw)
            except ValueError:
                parsed = raw.decode(errors="replace")
        if resp.status >= 400:
            if isinstance(parsed, dict):
                raise AgentError(
                    resp.status, str(parsed.get("error", "error")), parsed.get("detail"), parsed
                )
            raise AgentError(resp.status, "error", str(parsed) if parsed else None, parsed)
        return parsed

    # -- this box --------------------------------------------------------

    def identity(self) -> Json:
        """`{"peer_id", "alias", "registered"}`."""
        return self._call("GET", "/v1/identity")

    def status(self) -> Json:
        """Version, uptime, peer id, alias, route count and coord link state."""
        return self._call("GET", "/v1/status")

    def sessions(self) -> list[Json]:
        """Live visitor sessions: `[{"id", "kind", "transport", "age_secs"}]`."""
        return list(self._call("GET", "/v1/sessions")["sessions"])

    # -- apps ------------------------------------------------------------

    def apps(self) -> list[Json]:
        """Every app on this machine, with its public `url` when it has one."""
        return list(self._call("GET", "/v1/routes")["routes"])

    def app(self, name: str) -> Json | None:
        """One app, or `None` if there is no app by that name."""
        try:
            return self._call("GET", f"/v1/routes/{name}")
        except AgentError as e:
            if e.status == 404:
                return None
            raise

    def expose(
        self,
        name: str,
        *,
        port: int | None = None,
        socket_path: str | None = None,
        upstream: str | None = None,
        private: bool | None = None,
        auth_oauth: bool | list[str] | None = None,
    ) -> Json:
        """Register or replace an app. Give exactly one of `port`,
        `socket_path` or `upstream`.

        `private=True` makes it reachable only by peers it's shared with;
        `False` makes it public; `None` keeps an existing app's visibility
        (new apps are public). A `socket_path` upstream implies private.
        `auth_oauth=True` allows any OAuth provider the broker knows, a
        list restricts to those providers.
        """
        given = [x is not None for x in (port, socket_path, upstream)]
        if sum(given) != 1:
            raise ValueError("give exactly one of port, socket_path, upstream")
        if port is not None:
            upstream = f"http://127.0.0.1:{port}"
        elif socket_path is not None:
            if private is False:
                raise ValueError("a socket_path upstream is only allowed for private apps")
            upstream = _socket_upstream(socket_path)
            private = True
        if private and auth_oauth:
            raise ValueError("private apps can't use OAuth; access comes from shares")
        body: dict[str, Json] = {"name": name, "upstream": upstream}
        if auth_oauth:
            method: dict[str, Json] = {"kind": "oauth"}
            if isinstance(auth_oauth, list):
                if not auth_oauth:
                    raise ValueError("auth_oauth list must name at least one provider")
                method["providers"] = auth_oauth
            body["auth"] = [method]
        if private is not None:
            body["visibility"] = "private" if private else "public"
        return self._call("POST", "/v1/routes", body)

    def set_auth(self, name: str, auth_oauth: bool | list[str] | None) -> Json:
        """Change an existing public app's OAuth gate (`None` removes it)."""
        current = self.app(name)
        if current is None:
            raise AgentError(404, "not_found", f"no app named {name}")
        return self.expose(
            name,
            upstream=current["upstream"],
            private=current.get("visibility") == "private",
            auth_oauth=auth_oauth,
        )

    def unexpose(self, name: str) -> None:
        """Remove an app."""
        self._call("DELETE", f"/v1/routes/{name}")

    # -- shares ----------------------------------------------------------

    def shares(self) -> list[Json]:
        """`[{"app", "peers": [peer_id, ...]}]` for this machine's private apps."""
        return list(self._call("GET", "/v1/shares")["shares"])

    def share(self, app: str, peers: Iterable[str]) -> list[str]:
        """Let `peers` (z-base-32 peer ids) call private app `app`.
        Returns the app's full peer list."""
        table = self.shares()
        row = next((r for r in table if r["app"] == app), None)
        if row is None:
            row = {"app": app, "peers": []}
            table.append(row)
        for p in peers:
            if p not in row["peers"]:
                row["peers"].append(p)
        saved = self._call("PUT", "/v1/shares", {"shares": table})["shares"]
        return next((list(r["peers"]) for r in saved if r["app"] == app), [])

    def unshare(self, app: str, peer: str | None = None) -> None:
        """Revoke one peer, or every peer when `peer` is None. Takes
        effect on the next request; open connections run until they close."""
        table = self.shares()
        if peer is None:
            table = [r for r in table if r["app"] != app]
        else:
            for r in table:
                if r["app"] == app:
                    r["peers"] = [p for p in r["peers"] if p != peer]
        self._call("PUT", "/v1/shares", {"shares": table})

    # -- email -----------------------------------------------------------

    def email(self) -> Json:
        """Addresses, enabled flag, allowlist, unread count and rejection
        totals (`rejections` is None when coordination is unreachable)."""
        return self._call("GET", "/v1/email")

    def email_enable(self) -> Json:
        """Turn email on; coordination assigns `<alias>@<parent>`."""
        return self._call("PUT", "/v1/email", {"enabled": True})

    def email_disable(self) -> Json:
        """Turn email off. The inbox is kept."""
        return self._call("PUT", "/v1/email", {"enabled": False})

    def email_allow(self, addrs: Iterable[str]) -> list[str]:
        """Add senders to the allowlist. Returns the stored list."""
        table = list(self.email().get("allowlist", []))
        for a in addrs:
            n = _normalize_address(a)
            if n not in table:
                table.append(n)
        return list(self._call("PUT", "/v1/email/allowlist", {"allowlist": table})["allowlist"])

    def email_disallow(self, addr: str) -> list[str]:
        """Remove a sender from the allowlist. Returns the stored list."""
        target = _normalize_address(addr)
        table = [a for a in self.email().get("allowlist", []) if a != target]
        return list(self._call("PUT", "/v1/email/allowlist", {"allowlist": table})["allowlist"])

    def email_messages(self, unread: bool = False) -> list[Json]:
        """Inbox listing, newest first, without bodies."""
        path = "/v1/email/messages" + ("?unread=1" if unread else "")
        return list(self._call("GET", path)["messages"])

    def email_message(self, id: str, raw: bool = False) -> Json | bytes:
        """One message with its text/html bodies and attachment table, or
        the original RFC 5322 bytes with `raw=True`."""
        if raw:
            return self._call_bytes("GET", f"/v1/email/messages/{id}?format=raw")
        return self._call("GET", f"/v1/email/messages/{id}")

    def email_attachment(self, id: str, aid: str) -> bytes:
        """The bytes of attachment `aid` (from the message's `attachments`)."""
        return self._call_bytes("GET", f"/v1/email/messages/{id}/attachments/{aid}")

    def email_ack(self, id: str) -> Json:
        """Mark a message handled. It stays until deleted."""
        return self._call("POST", f"/v1/email/messages/{id}/ack")

    def email_delete(self, id: str) -> None:
        """Remove a message from the inbox."""
        self._call("DELETE", f"/v1/email/messages/{id}")

    def email_watch(self) -> Iterator[str]:
        """Yield the id of each message as it arrives. Blocks; catch up
        with `email_messages(unread=True)` on start, since messages that
        arrived earlier are not replayed."""
        conn, resp = self._open("GET", "/v1/email/messages?watch=1", {}, None, None)
        try:
            if resp.status >= 400:
                raw = resp.read()
                try:
                    parsed = json.loads(raw)
                except ValueError:
                    parsed = None
                if isinstance(parsed, dict):
                    raise AgentError(
                        resp.status, str(parsed.get("error", "error")), parsed.get("detail"), parsed
                    )
                raise AgentError(resp.status, "error", raw.decode(errors="replace") or None)
            while line := resp.readline():
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                if isinstance(event, dict) and isinstance(event.get("id"), str):
                    yield event["id"]
        finally:
            conn.close()

    def email_rejected(self) -> Json:
        """Senders coordination turned away: totals per reason and the
        most recent senders."""
        return self._call("GET", "/v1/email/rejected")

    # -- oauth grants ----------------------------------------------------

    def oauth_grants_providers(self) -> list[Json]:
        """Providers and scopes available through p2claw Connect:
        `[{"name", "scopes", "revoke_url"}]`."""
        return list(self._call("GET", "/v1/oauth-grants/providers")["providers"])

    def oauth_grants_start(
        self, provider: str, scopes: Iterable[str], code_challenge: str, nonce_hash: str
    ) -> Json:
        """Start a consent flow. `code_challenge` is the PKCE S256 challenge,
        `nonce_hash` the base64url SHA-256 of a one-time nonce. Returns
        `{"flow_id", "authorize_url"}`; show the URL to the user.

        :meth:`oauth_grants_connect` does all of this for you."""
        return self._call(
            "POST",
            "/v1/oauth-grants/flows",
            {
                "provider": provider,
                "scopes": list(scopes),
                "code_challenge": code_challenge,
                "nonce_hash": nonce_hash,
            },
        )

    def oauth_grants_wait(self, flow_id: str, timeout: float | None = None) -> Json:
        """Wait for the user to finish consenting. Returns the flow
        `{"status", "code", "state", "error"}` once its status is no longer
        `pending`, or the pending view when `timeout` seconds pass first."""
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            path = f"/v1/oauth-grants/flows/{flow_id}?wait=1"
            poll: float = _WAIT_POLL_SECONDS
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return self._call("GET", f"/v1/oauth-grants/flows/{flow_id}")
                poll = min(poll, max(1.0, remaining))
                path += f"&timeout={int(poll)}"
            view = self._call("GET", path, timeout=poll + 15)
            if view.get("status") != "pending":
                return view

    def oauth_grants_exchange(self, flow_id: str, code_verifier: str, store: bool = False) -> Json:
        """Exchange a finished flow for an access token. App-managed
        (`store=False`): `{"access_token", "expires_in", "scope", "provider",
        "grant"}`; keep `grant` and `provider` for :meth:`oauth_grants_refresh`.
        Agent-managed (`store=True`): the agent keeps the grant and returns
        `grant_id` instead; use :meth:`oauth_grants_token`."""
        return self._call(
            "POST",
            f"/v1/oauth-grants/flows/{flow_id}/exchange",
            {"code_verifier": code_verifier, "store": store},
        )

    def oauth_grants_refresh(self, grant: str, provider: str) -> Json:
        """New access token for an app-managed grant:
        `{"access_token", "expires_in", "scope", "grant"?}`. A returned `grant`
        replaces the stored one. Raises `AgentError` 410 `invalid_grant` when
        the provider no longer honours it."""
        return self._call(
            "POST", "/v1/oauth-grants/refresh", {"provider": provider, "grant": grant}
        )

    def oauth_grants(self) -> list[Json]:
        """Grants the agent keeps: `[{"id", "provider", "scopes", "created_at"}]`."""
        return list(self._call("GET", "/v1/oauth-grants")["grants"])

    def oauth_grants_token(self, grant_id: str) -> Json:
        """Current access token for a stored grant, refreshed as needed:
        `{"access_token", "expires_in", "scope"}`. Raises `AgentError` 410
        `invalid_grant` (and drops the grant) when the provider rejects it."""
        return self._call("GET", f"/v1/oauth-grants/{grant_id}/token")

    def oauth_grants_revoke(self, grant_id: str) -> Json:
        """Revoke a stored grant at the provider and forget it. The result's
        `provider_revoked` says whether the provider confirmed."""
        return self._call("DELETE", f"/v1/oauth-grants/{grant_id}")

    def oauth_grants_connect(
        self, provider: str, scopes: Iterable[str], *, store: bool = False
    ) -> OauthGrantFlow:
        """Start a consent flow with a fresh PKCE verifier and nonce. Show
        `flow.authorize_url` to the user, then call `flow.wait()` to get the
        exchange result once they approve."""
        code_verifier = secrets.token_urlsafe(64)
        nonce = secrets.token_urlsafe(32)
        started = self.oauth_grants_start(
            provider,
            scopes,
            _b64url_sha256(code_verifier.encode()),
            _b64url_sha256(nonce.encode()),
        )
        return OauthGrantFlow(self, started, provider, list(scopes), store, code_verifier, nonce)

    def _call_bytes(self, method: str, path: str) -> bytes:
        conn, resp = self._open(method, path, {}, None, self.timeout)
        try:
            raw = resp.read()
        finally:
            conn.close()
        if resp.status >= 400:
            try:
                parsed = json.loads(raw)
            except ValueError:
                parsed = None
            if isinstance(parsed, dict):
                raise AgentError(
                    resp.status, str(parsed.get("error", "error")), parsed.get("detail"), parsed
                )
            raise AgentError(resp.status, "error", raw.decode(errors="replace") or None)
        return raw

    # -- other boxes -----------------------------------------------------

    def fetch(
        self,
        peer: str,
        app: str,
        path: str = "/",
        *,
        method: str = "GET",
        headers: Mapping[str, str] | None = None,
        body: bytes | str | None = None,
        json_body: Json = None,
        timeout: float | None = None,
        stream: bool = False,
    ) -> Response | StreamingResponse:
        """Send an HTTP request to private app `app` on machine `peer`
        (alias or peer id), which must have shared it with this machine.

        Returns the app's response as-is. With `stream=True` the body is
        left unread on a :class:`StreamingResponse`.
        """
        if not path.startswith("/"):
            path = "/" + path
        hdrs = dict(headers or {})
        data: bytes | None
        if json_body is not None:
            data = json.dumps(json_body).encode()
            hdrs.setdefault("content-type", "application/json")
        elif isinstance(body, str):
            data = body.encode()
        else:
            data = body
        target = f"/v1/proxy/{peer}/{app}{path}"
        conn, resp = self._open(method, target, hdrs, data, timeout or self.timeout)
        if stream:
            return StreamingResponse(conn, resp)
        try:
            payload = resp.read()
        finally:
            conn.close()
        return Response(resp.status, resp.reason, resp.getheaders(), payload)

    def websocket(
        self,
        peer: str,
        app: str,
        path: str = "/",
        *,
        headers: Mapping[str, str] | None = None,
        open_timeout: float | None = 10.0,
    ) -> Any:
        """Open a WebSocket to private app `app` on machine `peer`.

        Returns a `websockets.sync.client.ClientConnection`
        (`send`, `recv`, `close`). Needs the `websocket` extra.
        """
        try:
            from websockets.sync.client import unix_connect
        except ImportError as e:  # pragma: no cover - depends on install
            raise ImportError(
                "websocket() needs the 'websockets' package: "
                "pip install 'p2claw-agent-client[websocket]'"
            ) from e
        if not path.startswith("/"):
            path = "/" + path
        return unix_connect(
            self.socket_path,
            f"ws://localhost/v1/proxy/{peer}/{app}{path}",
            additional_headers=dict(headers or {}),
            open_timeout=open_timeout,
        )


class OauthGrantFlow:
    """A consent flow started by :meth:`AgentClient.oauth_grants_connect`.
    Holds the PKCE verifier and nonce so :meth:`wait` can finish the flow."""

    def __init__(
        self,
        client: AgentClient,
        started: Json,
        provider: str,
        scopes: list[str],
        store: bool,
        code_verifier: str,
        nonce: str,
    ):
        self._client = client
        self.flow_id: str = started["flow_id"]
        self.authorize_url: str = started["authorize_url"]
        self.provider = provider
        self.scopes = scopes
        self.store = store
        self._code_verifier = code_verifier
        self._nonce_hash = _b64url_sha256(nonce.encode())

    def wait(self, timeout: float | None = None) -> Json:
        """Block until the user approves, check the callback carries this
        flow's nonce, and exchange. Returns what
        :meth:`AgentClient.oauth_grants_exchange` returns. Raises
        `TimeoutError` after `timeout` seconds, `AgentError` when the flow
        failed, expired or doesn't match."""
        view = self._client.oauth_grants_wait(self.flow_id, timeout)
        status = view.get("status")
        if status == "pending":
            raise TimeoutError(f"flow {self.flow_id} is still waiting for the user")
        if status != "ready":
            raise AgentError(0, f"flow_{status}", view.get("error"), view)
        if _state_nonce_hash(str(view.get("state", ""))) != self._nonce_hash:
            raise AgentError(0, "state_mismatch", "the callback is not for this flow", view)
        return self._client.oauth_grants_exchange(
            self.flow_id, self._code_verifier, store=self.store
        )

    def __repr__(self) -> str:
        return f"<OauthGrantFlow {self.flow_id} {self.provider}>"


def _b64url_sha256(data: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


def _state_nonce_hash(state: str) -> str | None:
    """The `nonce_hash` inside a broker-signed `state` (`s1.<json>.<sig>`).
    The signature is the broker's to check; the app only confirms the
    callback belongs to the flow it started."""
    parts = state.split(".")
    if len(parts) != 3 or parts[0] != "s1":
        return None
    try:
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(padded))
    except (ValueError, UnicodeDecodeError):
        return None
    nonce_hash = claims.get("nonce_hash") if isinstance(claims, dict) else None
    return nonce_hash if isinstance(nonce_hash, str) else None


def _normalize_address(addr: str) -> str:
    """The agent's canonical form: lower-case, plus-tag dropped."""
    s = addr.strip().lower()
    local, sep, domain = s.rpartition("@")
    if not sep or not local or not domain:
        raise ValueError(f"{addr!r} is not an email address")
    return f"{local.split('+', 1)[0]}@{domain}"


def _socket_upstream(path: str) -> str:
    abs_path = os.path.abspath(path)
    bad = next(
        (c for c in abs_path if c in _UNSAFE_SOCKET_CHARS or not c.isprintable() or c == " "), None
    )
    if bad is not None:
        raise ValueError(f"socket path {abs_path!r} contains {bad!r}")
    return f"unix:{abs_path}"
