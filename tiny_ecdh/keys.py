"""Typed key and secret objects for the educational ECDH package."""

from __future__ import annotations

from dataclasses import dataclass

from .errors import InvalidPrivateKeyError, InvalidPublicKeyError
from .utils import CURVE

__all__ = [
    "FIELD_BYTE_LENGTH",
    "PRIVATE_KEY_BYTE_LENGTH",
    "PUBLIC_KEY_BYTE_LENGTH",
    "PrivateKey",
    "PublicKey",
    "SharedSecret",
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
        if len(data) != PRIVATE_KEY_BYTE_LENGTH:
            raise InvalidPrivateKeyError(
                f"private key must be {PRIVATE_KEY_BYTE_LENGTH} bytes, got {len(data)}"
            )
        return cls(int.from_bytes(data, "big"))

    @classmethod
    def from_hex(cls, text: str) -> PrivateKey:
        """Parse a hex string, raising on malformed hex or wrong length."""
        try:
            data = bytes.fromhex(text)
        except ValueError as exc:
            raise InvalidPrivateKeyError(
                f"private key is not valid hex: {exc}"
            ) from exc
        return cls.from_bytes(data)


def _validate_field_element(name: str, value: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        raise InvalidPublicKeyError(f"public key {name} must be an int")
    if not (0 <= value < 2**CURVE.degree):
        raise InvalidPublicKeyError(f"public key {name} is out of range")


@dataclass(frozen=True)
class PublicKey:
    """A curve point derived from a private scalar."""

    x: int
    y: int

    def __post_init__(self) -> None:
        _validate_field_element("x", self.x)
        _validate_field_element("y", self.y)

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
        try:
            data = bytes.fromhex(text)
        except ValueError as exc:
            raise InvalidPublicKeyError(f"public key is not valid hex: {exc}") from exc
        return cls.from_bytes(data)


@dataclass(frozen=True)
class SharedSecret:
    """The raw, unhashed curve point agreed on by both parties."""

    x: int
    y: int
