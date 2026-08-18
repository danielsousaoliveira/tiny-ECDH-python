from dataclasses import FrozenInstanceError

import pytest

from tiny_ecdh import utils


def test_curve_is_one_immutable_object():
    assert utils.CURVE.degree == 163
    assert utils.CURVE.polynomial == 0x800000000000000000000000000000000000000C9
    assert utils.CURVE.a == 1
    assert utils.CURVE.b == 0x020A601907B8C953CA1481EB10512F78744A3205FD
    assert utils.CURVE.base_x == 0x00000003F0EBA16286A2D57EA0991168D4994637E8343E36
    assert utils.CURVE.base_y == 0x00000000D51FBC6C71A0094FA2CDD545B11C5C0C797324F1
    assert utils.CURVE.order == 0x040000000000000000000292FE77E70C12A4234C33
    with pytest.raises(FrozenInstanceError):
        utils.CURVE.a = 0


def test_generator_has_stated_order():
    assert utils.gf2point_on_curve(utils.CURVE.base_x, utils.CURVE.base_y)
    assert utils.gf2point_mul(
        utils.CURVE.base_x, utils.CURVE.base_y, utils.CURVE.order
    ) == (0, 0)
