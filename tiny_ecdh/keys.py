"""Typed key and secret objects for the educational ECDH package."""

from __future__ import annotations

from dataclasses import dataclass

from .errors import (
    InvalidPrivateKeyError,
    InvalidPublicKeyError,
    PublicKeyCoordinateRangeError,
    PublicKeyNotInSubgroupError,
    PublicKeyNotOnCurveError,
    PublicKeyPointAtInfinityError,
)
from .kdf import DEFAULT_SHARED_KEY_LENGTH, derive_shared_key
from .utils import CURVE, gf2point_is_zero, gf2point_mul, gf2point_on_curve

__all__ = [
    "FIELD_BYTE_LENGTH",
    "PRIVATE_KEY_BYTE_LENGTH",
    "PUBLIC_KEY_BYTE_LENGTH",
    "PrivateKey",
    "PublicKey",
    "SharedSecret",
    "validate_public_key_point",
]

#: Width in bytes of a single field element (ceil(CURVE.degree / 8)).
FIELD_BYTE_LENGTH = (CURVE.degree + 7) // 8

#: Fixed encoded width of a private key: one big-endian field element.
PRIVATE_KEY_BYTE_LENGTH = FIELD_BYTE_LENGTH

#: Fixed encoded width of a public key in SEC1 uncompressed form:
#: a 0x04 prefix followed by the big-endian x and y coordinates.
PUBLIC_KEY_BYTE_LENGTH = 1 + 2 * FIELD_BYTE_LENGTH

_UNCOMPRESSED_PREFIX = 0x04


@dataclass(frozen=True)
class PrivateKey:
    """A secret scalar. Never rendered in ``str()`` or ``repr()``."""

    scalar: int

    def __post_init__(self) -> None:
        if not isinstance(self.scalar, int) or isinstance(self.scalar, bool):
            raise InvalidPrivateKeyError("private key scalar must be an int")
        if not (1 <= self.scalar < CURVE.order):
            raise InvalidPrivateKeyError(
                f"private key must satisfy 1 <= scalar < {CURVE.order}"
            )

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(***)"

    def __str__(self) -> str:
        return repr(self)

    def to_bytes(self) -> bytes:
        """Encode as ``PRIVATE_KEY_BYTE_LENGTH`` big-endian bytes."""
        return self.scalar.to_bytes(PRIVATE_KEY_BYTE_LENGTH, "big")

    def to_hex(self) -> str:
        """Encode as a lowercase hex string of the fixed-width bytes."""
        return self.to_bytes().hex()

    @classmethod
    def from_bytes(cls, data: bytes) -> PrivateKey:
        """Parse fixed-width big-endian bytes, raising on any malformed input."""
        if not isinstance(data, (bytes, bytearray)):
            raise InvalidPrivateKeyError(
                f"private key must be bytes, got {type(data).__name__}"
            )
        if len(data) != PRIVATE_KEY_BYTE_LENGTH:
            raise InvalidPrivateKeyError(
                f"private key must be {PRIVATE_KEY_BYTE_LENGTH} bytes, got {len(data)}"
            )
        return cls(int.from_bytes(data, "big"))

    @classmethod
    def from_hex(cls, text: str) -> PrivateKey:
        """Parse a hex string, raising on malformed hex or wrong length."""
        if not isinstance(text, str):
            raise InvalidPrivateKeyError(
                f"private key hex must be a string, got {type(text).__name__}"
            )
        try:
            data = bytes.fromhex(text)
        except ValueError as exc:
            raise InvalidPrivateKeyError(
                f"private key is not valid hex: {exc}"
            ) from exc
        return cls.from_bytes(data)


def _validate_field_element(name: str, value: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        raise PublicKeyCoordinateRangeError(f"public key {name} must be an int")
    if not (0 <= value < 2**CURVE.degree):
        raise PublicKeyCoordinateRangeError(f"public key {name} is out of range")


def validate_public_key_point(x: int, y: int) -> None:
    """Validate a peer's public key point before it ever meets a secret scalar.

    Checks, in order, that ``x`` and ``y`` are in-range field elements, that
    the point is not the point at infinity, that it lies on the curve, and
    that it is a member of the curve's large prime-order subgroup. The
    infinity check must precede the on-curve check: the curve equation is
    satisfied by the point at infinity, so testing on-curve first would let
    infinity through as if it were a valid point.

    This does not, and cannot, verify that the point belongs to whoever
    claims it: this is unauthenticated key agreement, and validating a
    point's curve membership says nothing about the identity of its sender.
    """
    _validate_field_element("x", x)
    _validate_field_element("y", y)
    if gf2point_is_zero(x, y):
        raise PublicKeyPointAtInfinityError("public key is the point at infinity")
    if not gf2point_on_curve(x, y):
        raise PublicKeyNotOnCurveError("public key point is not on the curve")
    if not gf2point_is_zero(*gf2point_mul(x, y, CURVE.order)):
        raise PublicKeyNotInSubgroupError(
            "public key point is not a member of the curve's prime-order subgroup"
        )


@dataclass(frozen=True)
class PublicKey:
    """A curve point derived from a private scalar."""

    x: int
    y: int

    def __post_init__(self) -> None:
        validate_public_key_point(self.x, self.y)

    def to_bytes(self) -> bytes:
        """Encode in SEC1 uncompressed form: ``0x04 || x || y``, fixed width."""
        return (
            bytes([_UNCOMPRESSED_PREFIX])
            + self.x.to_bytes(FIELD_BYTE_LENGTH, "big")
            + self.y.to_bytes(FIELD_BYTE_LENGTH, "big")
        )

    def to_hex(self) -> str:
        """Encode as a lowercase hex string of the fixed-width bytes."""
        return self.to_bytes().hex()

    @classmethod
    def from_bytes(cls, data: bytes) -> PublicKey:
        """Parse SEC1 uncompressed bytes, raising on any malformed input."""
        if not isinstance(data, (bytes, bytearray)):
            raise InvalidPublicKeyError(
                f"public key must be bytes, got {type(data).__name__}"
            )
        if len(data) != PUBLIC_KEY_BYTE_LENGTH:
            raise InvalidPublicKeyError(
                f"public key must be {PUBLIC_KEY_BYTE_LENGTH} bytes, got {len(data)}"
            )
        if data[0] != _UNCOMPRESSED_PREFIX:
            raise InvalidPublicKeyError(
                f"public key must start with the uncompressed prefix "
                f"0x{_UNCOMPRESSED_PREFIX:02x}, got 0x{data[0]:02x}"
            )
        x = int.from_bytes(data[1 : 1 + FIELD_BYTE_LENGTH], "big")
        y = int.from_bytes(data[1 + FIELD_BYTE_LENGTH :], "big")
        return cls(x, y)

    @classmethod
    def from_hex(cls, text: str) -> PublicKey:
        """Parse a hex string, raising on malformed hex or wrong length."""
        if not isinstance(text, str):
            raise InvalidPublicKeyError(
                f"public key hex must be a string, got {type(text).__name__}"
            )
        try:
            data = bytes.fromhex(text)
        except ValueError as exc:
            raise InvalidPublicKeyError(f"public key is not valid hex: {exc}") from exc
        return cls.from_bytes(data)


@dataclass(frozen=True)
class SharedSecret:
    """The x coordinate of the curve point agreed on by both parties.

    ``raw_x`` is not a uniformly distributed key: a curve point's bits carry
    the algebraic structure of the curve equation, and it must never be used
    directly as symmetric key material. It is kept, under a name that makes
    reading it a visible decision, only for teaching value and for
    comparison against the original C implementation. The second coordinate
    is a deterministic function of the first and is discarded entirely --
    call ``derive_key`` for a key safe to actually use.
    """

    raw_x: int

    def derive_key(
        self, context: bytes, *, length: int = DEFAULT_SHARED_KEY_LENGTH
    ) -> bytes:
        """Derive a fixed-length key via HKDF-SHA256 over the x coordinate.

        ``context`` binds the derivation to a purpose, so the same key pair
        used for two purposes yields two different keys. Compare derived
        keys with ``tiny_ecdh.constant_time_compare``, never with ``==``.
        """
        return derive_shared_key(self.raw_x, FIELD_BYTE_LENGTH, context, length=length)
