"""Educational ECDH entry points for the NIST B-163 curve."""

from .entropy import EntropySource, default_entropy_source, random_scalar
from .errors import InvalidPublicKeyError
from .keys import PrivateKey, PublicKey, SharedSecret
from .utils import CURVE, gf2point_is_zero, gf2point_mul, gf2point_on_curve

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
    """Derive the shared secret point for ``private_key`` and a peer's public key."""
    x, y = peer_public_key.x, peer_public_key.y
    if (
        gf2point_is_zero(x, y)
        or not gf2point_on_curve(x, y)
        or not gf2point_is_zero(*gf2point_mul(x, y, CURVE.order))
    ):
        raise InvalidPublicKeyError("peer public key failed validation")
    secret_x, secret_y = gf2point_mul(x, y, private_key.scalar)
    return SharedSecret(secret_x, secret_y)
