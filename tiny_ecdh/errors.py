"""Exception hierarchy for the educational ECDH package."""

__all__ = [
    "InvalidPrivateKeyError",
    "InvalidPublicKeyError",
    "TinyECDHError",
]


class TinyECDHError(Exception):
    """Base class for every exception this package raises."""


class InvalidPrivateKeyError(TinyECDHError):
    """A private key scalar is out of the curve's valid range."""


class InvalidPublicKeyError(TinyECDHError):
    """A peer's public key failed on-curve or subgroup validation."""
