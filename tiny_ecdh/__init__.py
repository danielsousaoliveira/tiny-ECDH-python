"""Educational ECDH implementation for the NIST B-163 curve."""

from ._version import __version__
from .ecdh import ecdh_generate_keys, ecdh_shared_secret
from .errors import InvalidPrivateKeyError, InvalidPublicKeyError, TinyECDHError
from .keys import (
    FIELD_BYTE_LENGTH,
    PRIVATE_KEY_BYTE_LENGTH,
    PUBLIC_KEY_BYTE_LENGTH,
    PrivateKey,
    PublicKey,
    SharedSecret,
)

__all__ = [
    "FIELD_BYTE_LENGTH",
    "PRIVATE_KEY_BYTE_LENGTH",
    "PUBLIC_KEY_BYTE_LENGTH",
    "InvalidPrivateKeyError",
    "InvalidPublicKeyError",
    "PrivateKey",
    "PublicKey",
    "SharedSecret",
    "TinyECDHError",
    "__version__",
    "ecdh_generate_keys",
    "ecdh_shared_secret",
]
