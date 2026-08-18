"""Educational ECDH entry points for the NIST B-163 curve."""

from .utils import CURVE, gf2point_is_zero, gf2point_mul, gf2point_on_curve

__all__ = ["ecdh_generate_keys", "ecdh_shared_secret"]


def ecdh_generate_keys(private_key: int):
    """Return the private scalar and its public point as integer tuples."""
    private_key %= CURVE.order
    if private_key < 2**80:
        raise ValueError("private key must be at least 2**80")
    return private_key, gf2point_mul(CURVE.base_x, CURVE.base_y, private_key)


def ecdh_shared_secret(private_key: int, others_pub: tuple[int, int]):
    """Derive a peer point without mutating the caller's public point."""
    x, y = others_pub
    if (
        not (0 <= x < 2**CURVE.degree and 0 <= y < 2**CURVE.degree)
        or x == 0
        or gf2point_is_zero(x, y)
        or not gf2point_on_curve(x, y)
        or not gf2point_is_zero(*gf2point_mul(x, y, CURVE.order))
    ):
        return None
    return gf2point_mul(x, y, private_key)
