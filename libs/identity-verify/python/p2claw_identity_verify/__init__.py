"""Verify the X-P2claw-Identity-Token (EdDSA JWT) minted by p2claw agent."""

from ._errors import VerifyError, VerifyErrorKind
from ._peer_id import decode_peer_id, encode_peer_id
from ._verify import TOKEN_HEADER, Claims, verify

__all__ = [
    "Claims",
    "TOKEN_HEADER",
    "VerifyError",
    "VerifyErrorKind",
    "decode_peer_id",
    "encode_peer_id",
    "verify",
]

__version__ = "0.1.0a0"
