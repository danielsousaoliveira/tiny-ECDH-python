from tiny_ecdh import utils


def test_field_vectors():
    left = int(
        "00000001456789ab bcdef123 3456789a abcdef12 23456789".replace(" ", ""), 16
    )
    right = int(
        "0000000787654321 0fedcba9 87654321 0fedcba9 87654321".replace(" ", ""), 16
    )
    expected = int(
        "000000036bf43db1 89eb5411 49c6feff c2584634 623808f0".replace(" ", ""), 16
    )
    assert utils.gf2field_mul(left, right) == expected
    value = left
    inverse = int(
        "0000000373d5e900 b852eb09 ba8221c4 a5e48c24 ad88ec61".replace(" ", ""), 16
    )
    assert utils.gf2field_inv(value) == inverse


def test_point_vectors_and_group_order():
    g = (utils.base_x, utils.base_y)
    two_g = utils.gf2point_mul(*g, 2)
    three_g = utils.gf2point_mul(*g, 3)
    assert utils.gf2point_on_curve(*g)
    assert utils.gf2point_add(0, 0, *g) == g
    assert utils.gf2point_double(*g) == two_g
    assert utils.gf2point_add(*g, *two_g) == three_g
    assert utils.gf2point_mul(*g, utils.base_order) == (0, 0)
