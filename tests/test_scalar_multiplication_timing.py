from unittest.mock import patch

from tiny_ecdh import utils

SCALARS = [
    1,
    2,
    0b10101010,
    (1 << 162) - 1,
    1 << 162,
    utils.CURVE.order - 1,
    utils.CURVE.order - 2,
    utils.CURVE.order,
]


def _call_counts(scalar: int) -> tuple[int, int]:
    """(gf2field_inv calls, times gf2point_add's doubling branch would fire)
    while multiplying the base point by ``scalar``."""
    with (
        patch.object(utils, "gf2field_inv", wraps=utils.gf2field_inv) as inv_spy,
        patch.object(utils, "gf2point_add", wraps=utils.gf2point_add) as add_spy,
    ):
        utils.gf2point_mul(utils.CURVE.base_x, utils.CURVE.base_y, scalar)
        return inv_spy.call_count, add_spy.call_count


def test_iteration_count_is_fixed_regardless_of_scalar():
    with patch.object(
        utils, "_unified_double", wraps=utils._unified_double
    ) as double_spy:
        for scalar in SCALARS:
            double_spy.reset_mock()
            utils.gf2point_mul(utils.CURVE.base_x, utils.CURVE.base_y, scalar)
            assert double_spy.call_count == 2 * utils.CURVE.degree


def test_field_inversion_call_count_is_fixed_regardless_of_scalar():
    """Regression test: the old double-and-add-always loop still branched
    inside gf2point_add/gf2point_double, so the number of field inversions
    (and therefore the work per iteration) varied with the scalar even
    though the loop always ran CURVE.degree times. The unified, branch-free
    point operations must make this constant too."""
    counts = [_call_counts(scalar)[0] for scalar in SCALARS]
    assert len(set(counts)) == 1


def test_gf2point_add_is_never_called_by_gf2point_mul():
    """gf2point_mul must use the branch-free _unified_add internally, not
    the branching gf2point_add (whose doubling-via-addition case is what
    made the previous fixed-iteration-count fix still leak)."""
    counts = [_call_counts(scalar)[1] for scalar in SCALARS]
    assert counts == [0] * len(SCALARS)
