"""Structured error variants matching the cross-language test-vector vocabulary."""

from __future__ import annotations

from typing import Literal

VerifyErrorKind = Literal[
    "TokenMissing",
    "Malformed",
    "AlgorithmRejected",
    "BadSignature",
    "Expired",
    "NotYetValid",
    "IssuerMismatch",
]
"""Discriminant for verification failures. PascalCase strings match the
cross-language test-vector vocabulary used by the Rust / TypeScript /
Go reference libs.
"""


class VerifyError(Exception):
    """Raised when a presented token fails verification.

    Configuration errors (e.g. a malformed `trusted_peer_id`) raise
    `ValueError` instead — they're a programmer / operator issue, not
    a verification outcome.
    """

    kind: VerifyErrorKind

    def __init__(self, kind: VerifyErrorKind, message: str) -> None:
        super().__init__(message)
        self.kind = kind

    def __repr__(self) -> str:
        return f"VerifyError(kind={self.kind!r}, message={self.args[0]!r})"
