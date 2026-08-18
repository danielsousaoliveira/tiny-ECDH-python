"""HKDF-SHA256 key derivation and constant-time comparison for shared secrets.

A raw curve point is not a uniformly distributed value -- its bits carry the
algebraic structure of the curve equation -- so it must never be used
directly as symmetric key material. ``derive_shared_key`` runs the x
coordinate alone through HKDF (RFC 5869) over SHA-256 to produce a
fixed-length, uniformly distributed key, bound to a caller-supplied context
so the same key pair yields independent keys for independent purposes.
"""

from __future__ import annotations

import hashlib
import hmac

__all__ = ["DEFAULT_SHARED_KEY_LENGTH", "constant_time_compare", "derive_shared_key"]

#: Default output length in bytes for ``derive_shared_key`` (SHA-256 digest size).
DEFAULT_SHARED_KEY_LENGTH = 32

_HASH_LENGTH = hashlib.sha256().digest_size

#: RFC 5869 caps HKDF-Expand output at 255 times the underlying hash length.
_MAX_SHARED_KEY_LENGTH = 255 * _HASH_LENGTH


def _hkdf_extract(salt: bytes, input_key_material: bytes) -> bytes:
    return hmac.new(salt, input_key_material, hashlib.sha256).digest()


def _hkdf_expand(pseudorandom_key: bytes, info: bytes, length: int) -> bytes:
    output = b""
    previous_block = b""
    counter = 1
    while len(output) < length:
        previous_block = hmac.new(
            pseudorandom_key, previous_block + info + bytes([counter]), hashlib.sha256
        ).digest()
        output += previous_block
        counter += 1
    return output[:length]


def derive_shared_key(
    x: int,
    x_byte_length: int,
    context: bytes,
    *,
    length: int = DEFAULT_SHARED_KEY_LENGTH,
) -> bytes:
    """Derive a fixed-length key from the x coordinate of a shared point.

    ``context`` binds the derivation to a purpose: two derivations from the
    same ``x`` with different ``context`` values produce independent keys.
    ``length`` is the output size in bytes and does not depend on the curve's
    field size.
    """
    if not isinstance(context, (bytes, bytearray)):
        raise TypeError(f"context must be bytes, got {type(context).__name__}")
    if not isinstance(length, int) or isinstance(length, bool):
        raise TypeError(f"length must be an int, got {type(length).__name__}")
    if length <= 0:
        raise ValueError("length must be a positive number of bytes")
    if length > _MAX_SHARED_KEY_LENGTH:
        raise ValueError(
            f"length must be at most {_MAX_SHARED_KEY_LENGTH} bytes "
            f"(255 * {_HASH_LENGTH}-byte hash), got {length}"
        )
    input_key_material = x.to_bytes(x_byte_length, "big")
    pseudorandom_key = _hkdf_extract(b"\x00" * _HASH_LENGTH, input_key_material)
    return _hkdf_expand(pseudorandom_key, bytes(context), length)


def constant_time_compare(a: bytes | bytearray, b: bytes | bytearray) -> bool:
    """Compare two byte strings without leaking their contents through timing.

    Use this for every comparison of a derived key or shared secret; ``==``
    on bytes short-circuits at the first differing byte and is not safe for
    secret material.
    """
    if not isinstance(a, (bytes, bytearray)) or not isinstance(b, (bytes, bytearray)):
        raise TypeError("constant_time_compare requires bytes arguments")
    return hmac.compare_digest(a, b)
