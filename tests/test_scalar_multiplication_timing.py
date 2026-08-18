from unittest.mock import patch

from tiny_ecdh import utils


def _count_iterations(scalar: int) -> int:
    with patch.object(utils, "gf2point_double", wraps=utils.gf2point_double) as spy:
        utils.gf2point_mul(utils.CURVE.base_x, utils.CURVE.base_y, scalar)
        return spy.call_count


def test_iteration_count_is_fixed_regardless_of_scalar():
    scalars = [
        1,
        2,
        0b1,
        0b10101010,
        (1 << 162) - 1,
        1 << 162,
        utils.CURVE.order - 1,
        utils.CURVE.order,
    ]
    counts = [_count_iterations(scalar) for scalar in scalars]
    assert len(set(counts)) == 1
    assert counts[0] == utils.CURVE.degree
