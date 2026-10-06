"""Vector-driven test suite for the verify lib.

Loads the shared cross-language fixture at
`libs/identity-verify/test-vectors.json` and asserts:

  - `expect: "ok"` cases  → verify() returns expected_claims
  - `expect: "err:<Variant>"` cases → verify() raises VerifyError
    with `.kind == "<Variant>"`

The same JSON drives the Rust / TypeScript / Go reference libs.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from p2claw_identity_verify import TOKEN_HEADER, VerifyError, verify

# Canonical fixture is owned by native-dev's Rust gen-vectors binary.
# Falls back to the TS placeholder if the canonical isn't yet on disk.
_CANONICAL = Path(__file__).resolve().parents[2] / "test-vectors.json"
_PLACEHOLDER = Path(__file__).resolve().parents[2] / "ts" / ".placeholder-vectors.json"
FIXTURE_PATH = _CANONICAL if _CANONICAL.exists() else _PLACEHOLDER


def _load_fixture() -> dict[str, Any]:
    return json.loads(FIXTURE_PATH.read_text())


_FIXTURE = _load_fixture()


def _at(ts: int) -> datetime:
    return datetime.fromtimestamp(ts, tz=timezone.utc)


@pytest.mark.parametrize(
    "case",
    _FIXTURE["cases"],
    ids=lambda c: c["name"],
)
def test_case(case: dict[str, Any]) -> None:
    headers = {TOKEN_HEADER: case["token"]}
    now = _at(case["verify_at"])
    if case["expect"] == "ok":
        claims = verify(headers, _FIXTURE["trusted_peer_id"], now=now)
        for k, v in (case.get("expected_claims") or {}).items():
            assert claims.get(k) == v, f"claim {k!r} mismatch: {claims.get(k)!r} != {v!r}"
    else:
        expected_variant = case["expect"].removeprefix("err:")
        with pytest.raises(VerifyError) as exc_info:
            verify(headers, _FIXTURE["trusted_peer_id"], now=now)
        assert exc_info.value.kind == expected_variant


def test_missing_token_header() -> None:
    with pytest.raises(VerifyError) as exc_info:
        verify({}, _FIXTURE["trusted_peer_id"])
    assert exc_info.value.kind == "TokenMissing"


def test_invalid_trusted_peer_id_raises_value_error() -> None:
    headers = {TOKEN_HEADER: "not-relevant"}
    with pytest.raises(ValueError):
        verify(headers, "not-a-z-base-32-string")


def test_case_insensitive_header_lookup() -> None:
    positive = next(c for c in _FIXTURE["cases"] if c["expect"] == "ok")
    headers = {"X-P2claw-Identity-Token": positive["token"]}
    now = _at(positive["verify_at"])
    claims = verify(headers, _FIXTURE["trusted_peer_id"], now=now)
    assert claims["iss"] == _FIXTURE["trusted_peer_id"]


def test_error_class_attributes() -> None:
    err = VerifyError("TokenMissing", "x")
    assert err.kind == "TokenMissing"
    assert isinstance(err, Exception)
    assert "x" in str(err)
