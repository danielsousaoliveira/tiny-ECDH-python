"""Exception hierarchy for the educational ECDH package."""

__all__ = [
    "InvalidPrivateKeyError",
    "InvalidPublicKeyError",
    "InvalidSharedSecretError",
    "PublicKeyCoordinateRangeError",
    "PublicKeyNotInSubgroupError",
    "PublicKeyNotOnCurveError",
    "PublicKeyPointAtInfinityError",
    "TinyECDHError",
]


class TinyECDHError(Exception):
    """Base class for every exception this package raises."""


class InvalidPrivateKeyError(TinyECDHError):
    """A private key scalar is out of the curve's valid range."""


class InvalidPublicKeyError(TinyECDHError):
    """A peer's public key failed validation."""


class PublicKeyCoordinateRangeError(InvalidPublicKeyError):
    """A public key coordinate is not an element of the curve's field."""


class PublicKeyPointAtInfinityError(InvalidPublicKeyError):
    """A public key is the point at infinity."""


class PublicKeyNotOnCurveError(InvalidPublicKeyError):
    """A public key does not satisfy the curve equation."""


class PublicKeyNotInSubgroupError(InvalidPublicKeyError):
    """A public key is not a member of the curve's large prime-order subgroup."""


class InvalidSharedSecretError(TinyECDHError):
    """The key agreement produced the point at infinity as a shared secret."""
