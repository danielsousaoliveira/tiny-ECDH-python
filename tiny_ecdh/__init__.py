"""Educational ECDH implementation for the NIST B-163 curve."""

from ._version import __version__
from .ecdh import ecdh_generate_keys, ecdh_shared_secret
from .errors import (
    InvalidPrivateKeyError,
    InvalidPublicKeyError,
    InvalidSharedSecretError,
    PublicKeyCoordinateRangeError,
    PublicKeyNotInSubgroupError,
    PublicKeyNotOnCurveError,
    PublicKeyPointAtInfinityError,
    TinyECDHError,
)
from .kdf import DEFAULT_SHARED_KEY_LENGTH, constant_time_compare, derive_shared_key
from .keys import (
    FIELD_BYTE_LENGTH,
    PRIVATE_KEY_BYTE_LENGTH,
    PUBLIC_KEY_BYTE_LENGTH,
    PrivateKey,
    PublicKey,
    SharedSecret,
    validate_public_key_point,
)

__all__ = [
    "DEFAULT_SHARED_KEY_LENGTH",
    "FIELD_BYTE_LENGTH",
    "PRIVATE_KEY_BYTE_LENGTH",
    "PUBLIC_KEY_BYTE_LENGTH",
    "InvalidPrivateKeyError",
    "InvalidPublicKeyError",
    "InvalidSharedSecretError",
    "PrivateKey",
    "PublicKey",
    "PublicKeyCoordinateRangeError",
    "PublicKeyNotInSubgroupError",
    "PublicKeyNotOnCurveError",
    "PublicKeyPointAtInfinityError",
    "SharedSecret",
    "TinyECDHError",
    "__version__",
    "constant_time_compare",
    "derive_shared_key",
    "ecdh_generate_keys",
    "ecdh_shared_secret",
    "validate_public_key_point",
]
