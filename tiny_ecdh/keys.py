"""Typed key and secret objects for the educational ECDH package."""

from dataclasses import dataclass

__all__ = ["PrivateKey", "PublicKey", "SharedSecret"]


@dataclass(frozen=True)
class PrivateKey:
    """A secret scalar. Never rendered in ``str()`` or ``repr()``."""

    scalar: int

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(***)"

    def __str__(self) -> str:
        return repr(self)


@dataclass(frozen=True)
class PublicKey:
    """A curve point derived from a private scalar."""

    x: int
    y: int


@dataclass(frozen=True)
class SharedSecret:
    """The raw, unhashed curve point agreed on by both parties."""

    x: int
    y: int
