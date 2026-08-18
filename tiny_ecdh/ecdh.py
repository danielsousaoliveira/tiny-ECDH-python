"""Educational ECDH entry points for the NIST B-163 curve."""

from .entropy import EntropySource, default_entropy_source, random_scalar
from .errors import InvalidSharedSecretError
from .keys import PrivateKey, PublicKey, SharedSecret, validate_public_key_point
from .utils import CURVE, gf2point_is_zero, gf2point_mul

__all__ = ["ecdh_generate_keys", "ecdh_shared_secret"]


def ecdh_generate_keys(
    *, entropy_source: EntropySource = default_entropy_source
) -> tuple[PrivateKey, PublicKey]:
    """Generate a private key and its public point from CSPRNG entropy.

    ``entropy_source`` is only for tests that need a deterministic, named
    stand-in; the default draws from the operating system's entropy source
    and is never seedable.
    """
    private_key = PrivateKey(random_scalar(entropy_source))
    x, y = gf2point_mul(CURVE.base_x, CURVE.base_y, private_key.scalar)
    return private_key, PublicKey(x, y)


def ecdh_shared_secret(
    private_key: PrivateKey, peer_public_key: PublicKey
) -> SharedSecret:
    """Derive the shared secret point for ``private_key`` and a peer's public key.

    Validation runs to completion before the private scalar touches the
    peer's point at all, so a rejected key never leaks anything about the
    scalar through the point multiplication it would otherwise feed.
    """
    x, y = peer_public_key.x, peer_public_key.y
    validate_public_key_point(x, y)
    secret_x, secret_y = gf2point_mul(x, y, private_key.scalar)
    if gf2point_is_zero(secret_x, secret_y):
        raise InvalidSharedSecretError("key agreement produced the point at infinity")
    return SharedSecret(secret_x, secret_y)
