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


def _unified_double(x: int, y: int) -> tuple[int, int]:
    """Point doubling that always does the same field operations.

    ``gf2point_double`` branches on whether ``(x, y)`` is the identity, to
    avoid inverting zero. Here that case is instead selected away after
    always computing the ordinary-point formula against a substituted safe
    input, so the call shape doesn't depend on which case applies.
    """
    is_identity = int(bitvec_is_zero(x))
    safe_x = _select_int(is_identity, 1, x)
    slope = gf2field_add(gf2field_mul(y, gf2field_inv(safe_x)), safe_x)
    new_x = gf2field_add(gf2field_add(gf2field_mul(slope, slope), slope), CURVE.a)
    new_y = gf2field_add(
        gf2field_mul(x, x), gf2field_mul(gf2field_add(slope, 1), new_x)
    )
    return _select_point(is_identity, (0, 0), (new_x, new_y))


def _unified_add(x1: int, y1: int, x2: int, y2: int) -> tuple[int, int]:
    """Point addition that always does the same field operations.

    ``gf2point_add`` branches four ways (either operand the identity, equal
    x-coordinates doubling, equal x-coordinates summing to the identity,
    the general case), and the equal-x case recurses into a doubling call —
    which is why the plain double-and-add-always ladder still leaked: how
    often the running total coincides with the point being added is
    scalar-dependent, and each coincidence added an extra doubling call.
    Here every case is always computed, against inputs substituted to keep
    the field inversion from ever dividing by zero, and the right one is
    selected without a Python-level branch.
    """
    x1_is_identity = int(gf2point_is_zero(x1, y1))
    x2_is_identity = int(gf2point_is_zero(x2, y2))
    same_x = int(x1 == x2)
    same_y = int(y1 == y2)
    is_doubling = same_x & same_y
    sums_to_identity = same_x & (1 - same_y)

    denom = gf2field_add(x1, x2)
    safe_denom = _select_int(same_x, 1, denom)
    slope = gf2field_mul(gf2field_add(y1, y2), gf2field_inv(safe_denom))
    generic_x = gf2field_add(
        gf2field_add(gf2field_mul(slope, slope), slope),
        gf2field_add(x1, gf2field_add(x2, CURVE.a)),
    )
    generic_y = gf2field_add(
        gf2field_mul(slope, gf2field_add(x1, generic_x)), gf2field_add(generic_x, y1)
    )

    doubled = _unified_double(x1, y1)
    result = _select_point(
        is_doubling,
        doubled,
        _select_point(sums_to_identity, (0, 0), (generic_x, generic_y)),
    )
    result = _select_point(x2_is_identity, (x1, y1), result)
    result = _select_point(x1_is_identity, (x2, y2), result)
    return result


def _double_and_add_always(x: int, y: int, exp: int, bit_width: int) -> tuple[int, int]:
    result = gf2point_set_zero()
    for bit_index in range(bit_width - 1, -1, -1):
        result = _unified_double(*result)
        added = _unified_add(*result, x, y)
        result = _select_point(bitvec_get_bit(exp, bit_index), added, result)
    return result


def gf2point_mul(x: int, y: int, exp: int) -> tuple[int, int]:
    """Multiply a point; educational only, not suitable for production.

    Always runs ``CURVE.degree`` double-and-add-always iterations built from
    ``_unified_double``/``_unified_add``, so both the iteration count and the
    field operations performed each iteration are the same for every ``exp``:
    which of ``_unified_add``'s internal cases applies (identity operand,
    doubling, summing to the identity, or the general case) only changes
    which precomputed candidate a branch-free select picks, never how much
    work is done or which functions are called.

    This does not make the implementation constant-time. Field inversion
    (called once per ``_unified_double`` and once per ``_unified_add``, so
    twice per iteration here) is variable-time extended-Euclid, and the
    interpreter's own arbitrary-precision arithmetic takes time that varies
    with operand size. Both are data-dependent regardless of how this
    function is shaped, and closing them is out of scope for this function.
    """
    return _double_and_add_always(x, y, exp, CURVE.degree)


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
