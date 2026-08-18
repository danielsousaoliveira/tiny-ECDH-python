from dataclasses import FrozenInstanceError

import pytest

from tiny_ecdh import utils


def test_curve_is_one_immutable_object():
    assert utils.CURVE.degree == 163
    assert utils.CURVE.polynomial == utils.polynomial
    assert utils.CURVE.base_x == utils.base_x
    assert utils.CURVE.base_y == utils.base_y
    assert utils.gf2point_on_curve(utils.CURVE.base_x, utils.CURVE.base_y)
    with pytest.raises(FrozenInstanceError):
        utils.CURVE.a = 0


def test_generator_has_stated_order():
    assert utils.gf2point_mul(
        utils.CURVE.base_x, utils.CURVE.base_y, utils.CURVE.order
    ) == (0, 0)
