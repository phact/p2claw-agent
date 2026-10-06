"""Main verify entry point — thin wrapper over PyJWT + cryptography."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from typing import Any, Mapping

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ._errors import VerifyError
from ._peer_id import decode_peer_id

#: Canonical header the daemon mints into.
TOKEN_HEADER = "x-p2claw-identity-token"

#: Clock-skew tolerance applied to `exp`/`nbf`. Attestations live 60s;
#: 15s leeway in either direction.
_LEEWAY_SECONDS = 15

Claims = dict[str, Any]
"""Verified identity claims: `sub`/`iss`/`iat`/`exp`/`email`/`name`/
`auth_method`; the dict is open-ended so additive
claim fields appear here without an API change.
"""


def verify(
    headers: Mapping[str, str] | Mapping[str, list[str]] | Any,
    trusted_peer_id: str,
    now: datetime | None = None,
) -> Claims:
    """Verify the `X-P2claw-Identity-Token` against `trusted_peer_id`.

    Args:
        headers: Mapping (or anything with `.get(name)`) carrying the
            request headers; case-insensitive lookup.
        trusted_peer_id: Operator-supplied z-base-32 peer_id from app
            config — IS the box's Ed25519 pubkey.
        now: Reference time (mostly for tests). Defaults to UTC now.

    Returns:
        The verified `Claims` dict on success. `claims["iss"]` is
        guaranteed to equal `trusted_peer_id`.

    Raises:
        VerifyError: any verification failure — `.kind` is the
            structured discriminant (`Expired`, `BadSignature`, etc.).
        ValueError: if `trusted_peer_id` isn't valid z-base-32 (this
            is a configuration mistake, not a verification outcome).
    """
    pubkey_bytes = decode_peer_id(trusted_peer_id)

    token = _read_header(headers, TOKEN_HEADER)
    if not token:
        raise VerifyError("TokenMissing", f"no {TOKEN_HEADER} header")

    # Peek the JOSE header's `alg` before handing the token to PyJWT.
    # PyJWT classifies non-allow-listed algs correctly today, but the
    # peek-first pattern matches the Rust reference lib's
    # defence-in-depth: AlgorithmRejected is the discriminant on alg
    # mismatch regardless of how the underlying library wraps the
    # rejection.
    peeked_alg = _peek_jose_alg(token)
    if peeked_alg is not None and peeked_alg != "EdDSA":
        raise VerifyError("AlgorithmRejected", f"alg={peeked_alg!r} is not EdDSA")

    public_key = Ed25519PublicKey.from_public_bytes(pubkey_bytes)
    reference = now if now is not None else datetime.now(timezone.utc)

    try:
        # PyJWT's `decode` enforces `algorithms=` whitelist BEFORE any
        # crypto runs — that's the alg-confusion defence. We disable
        # PyJWT's exp/nbf checks here because they pin against the
        # wall clock; the temporal checks below run against the
        # caller-supplied `now` so vectors stay evergreen.
        payload = jwt.decode(
            token,
            public_key,
            algorithms=["EdDSA"],
            options={
                "verify_signature": True,
                "verify_exp": False,
                "verify_nbf": False,
                "verify_iat": False,
            },
        )
    except jwt.InvalidAlgorithmError as e:
        raise VerifyError("AlgorithmRejected", str(e)) from e
    except jwt.InvalidSignatureError as e:
        raise VerifyError("BadSignature", str(e)) from e
    except jwt.DecodeError as e:
        # Covers truncated/malformed/non-JWS input.
        raise VerifyError("Malformed", str(e)) from e
    except jwt.InvalidTokenError as e:
        # Catch-all for any other jwt.InvalidTokenError subclass.
        raise VerifyError("Malformed", str(e)) from e

    _check_temporal(payload, reference)

    # Defence-in-depth: even if signature verifies, the `iss` claim
    # must match the trusted peer_id.
    if payload.get("iss") != trusted_peer_id:
        raise VerifyError(
            "IssuerMismatch",
            f"iss={payload.get('iss')!r} does not match trusted peer_id",
        )

    return payload


def _read_header(headers: Any, name: str) -> str | None:
    """Case-insensitive header lookup for both dict-likes and Headers-likes.

    Tries the original-case key first (works for HTTP frameworks that
    expose a case-insensitive dict — Starlette, Werkzeug), then the
    lowercased key, then falls back to iterating the keys and matching
    lowercased. The fallback is what makes plain `dict` inputs work.
    """
    lower = name.lower()
    if hasattr(headers, "get") and callable(headers.get):
        v = headers.get(name)
        if v is None:
            v = headers.get(lower)
        if v is not None:
            return v[0] if isinstance(v, list) else v
    try:
        for k in headers:  # type: ignore[union-attr]
            if str(k).lower() == lower:
                v = headers[k]  # type: ignore[index]
                return v[0] if isinstance(v, list) else v
    except TypeError:
        return None
    return None


def _peek_jose_alg(token: str) -> str | None:
    """Decode the JOSE header's `alg` field by hand.

    Returns the alg string on success, or `None` if the token doesn't
    even parse as a JWS header. Those cases are left for PyJWT's full
    decode to classify as ``Malformed``.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        pad = "=" * (-len(parts[0]) % 4)
        header_bytes = base64.urlsafe_b64decode(parts[0] + pad)
        header = json.loads(header_bytes.decode("utf-8"))
    except Exception:
        return None
    alg = header.get("alg") if isinstance(header, dict) else None
    return alg if isinstance(alg, str) else None


def _check_temporal(payload: Claims, now: datetime) -> None:
    """Check exp/nbf/iat against an explicit `now` with spec leeway.

    PyJWT (like jose) only validates `nbf` for not-before semantics;
    the canonical fixture's `not_yet_valid` case uses `iat` in the
    future (no `nbf`), so we enforce iat-future too.
    """
    now_ts = int(now.timestamp())
    exp = payload.get("exp")
    nbf = payload.get("nbf")
    iat = payload.get("iat")
    if isinstance(exp, (int, float)) and now_ts > int(exp) + _LEEWAY_SECONDS:
        raise VerifyError("Expired", f"exp={int(exp)} < now={now_ts}")
    if isinstance(nbf, (int, float)) and now_ts + _LEEWAY_SECONDS < int(nbf):
        raise VerifyError("NotYetValid", f"nbf={int(nbf)} > now={now_ts}")
    if isinstance(iat, (int, float)) and now_ts + _LEEWAY_SECONDS < int(iat):
        raise VerifyError("NotYetValid", f"iat={int(iat)} > now={now_ts}")
