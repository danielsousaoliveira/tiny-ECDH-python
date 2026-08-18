"""Known-answer vectors for the SEC2 sect163r2 arithmetic.

The expected words below were independently calculated from the SEC 2
polynomial and point formulas (SEC 2 v2, section 2.2.1 and 3.2.3), using
the reference C implementation as a second check.  They are deliberately
stored as words rather than numpy arrays so a representation rewrite keeps
the same answers.
"""

import numpy as np

from tiny_ecdh import utils

SOURCE = "SEC 2 v2, sections 2.2.1 and 3.2.3; cross-checked against kokke/tiny-ECDH-c"


def words(value):
    return np.array(value, dtype=np.uint32)


def point(value):
    return words(value[0]), words(value[1])


G = (utils.base_x, utils.base_y)
TWO_G = (
    [1540670164, 2792184504, 168580638, 2622087200, 2930982893, 1],
    [3358103016, 1979540060, 1277167460, 3444035778, 811630994, 5],
)
THREE_G = (
    [3990262270, 2422641142, 10317723, 4167738133, 872416631, 6],
    [3693228222, 898088261, 3875251557, 1815003156, 27516429, 4],
)


def test_field_multiplication_vector():
    left = words([0x23456789, 0xABCDEF12, 0x3456789A, 0xBCDEF123, 0x456789AB, 1])
    right = words([0x87654321, 0x0FEDCBA9, 0x87654321, 0x0FEDCBA9, 0x87654321, 7])
    expected = words([1647839472, 3260565044, 1237778175, 2313901073, 1811168689, 3])
    assert np.array_equal(utils.gf2field_mul(words([0] * 6), left, right), expected)


def test_field_inversion_vector():
    value = words([0x23456789, 0xABCDEF12, 0x3456789A, 0xBCDEF123, 0x456789AB, 1])
    expected = words([2911431777, 2783218724, 3129090500, 3092441865, 1943398656, 3])
    assert np.array_equal(utils.gf2field_inv(words([0] * 6), value), expected)


def test_generator_is_on_curve_and_identity_addition_is_neutral():
    gx, gy = point(G)
    zero_x = words([0] * 6)
    zero_y = words([0] * 6)
    assert utils.gf2point_on_curve(gx, gy)
    result = utils.gf2point_add(zero_x, zero_y, gx, gy)
    assert np.array_equal(result[0], gx)
    assert np.array_equal(result[1], gy)


def test_point_doubling_and_addition_vectors():
    gx, gy = point(G)
    tx, ty = point(TWO_G)
    expected_x, expected_y = point(THREE_G)
    assert np.array_equal(utils.gf2point_double(gx.copy(), gy.copy())[0], tx)
    assert np.array_equal(utils.gf2point_double(gx.copy(), gy.copy())[1], ty)
    actual = utils.gf2point_add(gx.copy(), gy.copy(), tx, ty)
    assert np.array_equal(actual[0], expected_x)
    assert np.array_equal(actual[1], expected_y)


def test_small_scalar_multiples_and_group_order_identity():
    for scalar, expected in ((1, G), (2, TWO_G), (3, THREE_G)):
        x, y = point(G)
        exponent = words([scalar, 0, 0, 0, 0, 0])
        actual = utils.gf2point_mul(x, y, exponent)
        expected_x, expected_y = point(expected)
        assert np.array_equal(actual[0], words(expected_x))
        assert np.array_equal(actual[1], words(expected_y))

    x, y = point(G)
    actual = utils.gf2point_mul(x, y, words(utils.base_order))
    assert utils.gf2point_is_zero(*actual)
