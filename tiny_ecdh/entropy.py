"""CSPRNG-backed scalar sampling for private key generation.

``default_entropy_source`` is the only entropy path reachable by default and is
never seedable. ``random_scalar`` accepts an ``entropy_source`` override so
tests can rig a deterministic byte stream, but that override must always be
passed explicitly and by name -- there is no default that quietly weakens it.
"""

import secrets
from typing import Callable

from .utils import CURVE

__all__ = ["default_entropy_source", "random_scalar"]

EntropySource = Callable[[int], bytes]

default_entropy_source: EntropySource = secrets.token_bytes


def random_scalar(entropy_source: EntropySource = default_entropy_source) -> int:
    """Draw a scalar uniformly from ``[1, CURVE.order)`` by rejection sampling.

    Out-of-range draws (including zero) are discarded and redrawn rather than
    masked or reduced into range, so every valid scalar is equally likely and
    none of the range is unreachable.
    """
    bit_length = CURVE.order.bit_length()
    byte_length = (bit_length + 7) // 8
    excess_bits = byte_length * 8 - bit_length
    top_byte_mask = 0xFF >> excess_bits
    while True:
        raw = bytearray(entropy_source(byte_length))
        raw[0] &= top_byte_mask
        candidate = int.from_bytes(bytes(raw), "big")
        if 1 <= candidate < CURVE.order:
            return candidate
