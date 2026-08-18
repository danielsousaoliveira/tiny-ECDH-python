"""Integer arithmetic for the educational NIST B-163 implementation."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Curve:
    degree: int
    polynomial: int
    a: int
    b: int
    base_x: int
    base_y: int
    order: int
    cofactor: int


CURVE = Curve(
    degree=163,
    polynomial=(1 << 163) | (1 << 7) | (1 << 6) | (1 << 3) | 1,
    a=1,
    b=0x020A601907B8C953CA1481EB10512F78744A3205FD,
    base_x=0x00000003F0EBA16286A2D57EA0991168D4994637E8343E36,
    base_y=0x00000000D51FBC6C71A0094FA2CDD545B11C5C0C797324F1,
    order=0x040000000000000000000292FE77E70C12A4234C33,
    cofactor=2,
)

CURVE_DEGREE = CURVE.degree
polynomial = CURVE.polynomial
coeff_a = CURVE.a
coeff_b = CURVE.b
base_x = CURVE.base_x
base_y = CURVE.base_y
base_order = CURVE.order
cofactor = CURVE.cofactor


def bitvec_get_bit(x: int, idx: int) -> int:
    return (x >> idx) & 1


def bitvec_is_zero(x: int) -> bool:
    return x == 0


def gf2field_add(x: int, y: int) -> int:
    return x ^ y


def gf2field_inc(x: int) -> int:
    return x ^ 1


def gf2field_mul(x: int, y: int) -> int:
    """Multiply reduced field elements; inputs must fit in ``CURVE.degree`` bits."""
    if x.bit_length() > CURVE.degree or y.bit_length() > CURVE.degree:
        raise ValueError("field element exceeds curve degree")
    result = 0
    while y:
        if y & 1:
            result ^= x
        y >>= 1
        x <<= 1
        if x >> CURVE.degree:
            x ^= CURVE.polynomial
    return result


def gf2field_inv(x: int) -> int:
    if x.bit_length() > CURVE.degree:
        raise ValueError("field element exceeds curve degree")
    if x == 0:
        raise ZeroDivisionError("cannot invert zero")
    u, v = x, CURVE.polynomial
    g1, g2 = 1, 0
    while u != 1:
        shift = u.bit_length() - v.bit_length()
        if shift < 0:
            u, v = v, u
            g1, g2 = g2, g1
            shift = -shift
        u ^= v << shift
        g1 ^= g2 << shift
    return g1


def gf2point_is_zero(x: int, y: int) -> bool:
    return bool((x == 0) & (y == 0))


def gf2point_set_zero() -> tuple[int, int]:
    return 0, 0


def gf2point_copy(x: int, y: int) -> tuple[int, int]:
    return x, y


def gf2point_double(x: int, y: int) -> tuple[int, int]:
    if x == 0:
        return 0, 0
    slope = gf2field_add(gf2field_mul(y, gf2field_inv(x)), x)
    new_x = gf2field_add(gf2field_add(gf2field_mul(slope, slope), slope), CURVE.a)
    new_y = gf2field_add(
        gf2field_mul(x, x), gf2field_mul(gf2field_add(slope, 1), new_x)
    )
    return new_x, new_y


def gf2point_add(x1: int, y1: int, x2: int, y2: int) -> tuple[int, int]:
    if gf2point_is_zero(x2, y2):
        return x1, y1
    if gf2point_is_zero(x1, y1):
        return x2, y2
    if x1 == x2:
        return gf2point_double(x1, y1) if y1 == y2 else (0, 0)
    slope = gf2field_mul(gf2field_add(y1, y2), gf2field_inv(gf2field_add(x1, x2)))
    new_x = gf2field_add(
        gf2field_add(gf2field_mul(slope, slope), slope),
        gf2field_add(x1, gf2field_add(x2, CURVE.a)),
    )
    new_y = gf2field_add(
        gf2field_mul(slope, gf2field_add(x1, new_x)), gf2field_add(new_x, y1)
    )
    return new_x, new_y


def _select_int(bit: int, on_true: int, on_false: int) -> int:
    """Return ``on_true`` if ``bit`` is 1 else ``on_false``, without branching on ``bit``."""
    mask = -bit
    return (on_true & mask) | (on_false & ~mask)


def _select_point(
    bit: int, on_true: tuple[int, int], on_false: tuple[int, int]
) -> tuple[int, int]:
    return (
        _select_int(bit, on_true[0], on_false[0]),
        _select_int(bit, on_true[1], on_false[1]),
    )


def gf2point_mul(x: int, y: int, exp: int) -> tuple[int, int]:
    """Multiply a point; educational only, not suitable for production.

    Always runs ``CURVE.degree`` double-and-add-always iterations, so the
    iteration count and the sequence of operations do not depend on ``exp``.
    This does not make the implementation constant-time: field inversion
    (called from every double and add) is variable-time extended-Euclid, and
    the interpreter's own arbitrary-precision arithmetic takes time that
    varies with operand size. Those leaks are out of scope for this function.
    """
    result = gf2point_set_zero()
    for bit_index in range(CURVE.degree - 1, -1, -1):
        result = gf2point_double(*result)
        added = gf2point_add(*result, x, y)
        result = _select_point(bitvec_get_bit(exp, bit_index), added, result)
    return result


def gf2point_on_curve(x: int, y: int) -> bool:
    if gf2point_is_zero(x, y):
        return True
    left = gf2field_add(gf2field_mul(y, y), gf2field_mul(x, y))
    right = gf2field_add(
        gf2field_add(
            gf2field_mul(gf2field_mul(x, x), x),
            gf2field_mul(CURVE.a, gf2field_mul(x, x)),
        ),
        CURVE.b,
    )
    return left == right
