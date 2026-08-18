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
    g = (
        0x00000003F0EBA16286A2D57EA0991168D4994637E8343E36,
        0x00000000D51FBC6C71A0094FA2CDD545B11C5C0C797324F1,
    )
    two_g = (
        0x00000001AEB33FED9C49E0200A0C561EA66D5AB85BD4C2D4,
        0x0000000530608192CD47D0C24C20076475FD625CC82895E8,
    )
    three_g = (
        0x0000000634000577F86AA315009D6F9B906691F6EDD691FE,
        0x0000000401A3DE0D6C2EC014E6FBA5653587BD45DC2230BE,
    )
    order = 0x040000000000000000000292FE77E70C12A4234C33
    assert utils.gf2point_on_curve(*g)
    assert utils.gf2point_add(0, 0, *g) == g
    assert utils.gf2point_double(*g) == two_g
    assert utils.gf2point_add(*g, *two_g) == three_g
    assert utils.gf2point_mul(*g, order) == (0, 0)
