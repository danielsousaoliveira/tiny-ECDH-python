"""Typed key and secret objects for the educational ECDH package."""

from dataclasses import dataclass

from .errors import InvalidPrivateKeyError, InvalidPublicKeyError
from .utils import CURVE

__all__ = ["PrivateKey", "PublicKey", "SharedSecret"]


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


@dataclass(frozen=True)
class SharedSecret:
    """The raw, unhashed curve point agreed on by both parties."""

    x: int
    y: int
