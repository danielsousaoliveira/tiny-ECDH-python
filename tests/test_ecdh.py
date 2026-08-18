import pytest

from tiny_ecdh import (
    InvalidPrivateKeyError,
    InvalidPublicKeyError,
    PrivateKey,
    PublicKey,
    PublicKeyCoordinateRangeError,
    PublicKeyNotInSubgroupError,
    PublicKeyNotOnCurveError,
    PublicKeyPointAtInfinityError,
    ecdh_generate_keys,
    ecdh_shared_secret,
    utils,
    validate_public_key_point,
)

#: A point of order 2: x=0 satisfies the curve equation y**2 == b, and
#: doubling a point with x=0 collapses straight to the identity, so this
#: point lies outside the large prime-order subgroup. It passes the
#: infinity and on-curve checks and must be rejected only by the subgroup
#: check.
_SMALL_ORDER_Y = 0x2C25B85BADF8927593D21C366DA89C03969F34DA5


def test_key_exchange_and_immutable_inputs():
    private_a, public_a = ecdh_generate_keys()
    private_b, public_b = ecdh_generate_keys()
    assert isinstance(private_a, PrivateKey)
    assert isinstance(public_a, PublicKey)
    public_b_before = public_b
    secret_a = ecdh_shared_secret(private_a, public_b)
    secret_b = ecdh_shared_secret(private_b, public_a)
    assert secret_a == secret_b
    assert public_b == public_b_before


def test_manually_constructed_private_key_out_of_range_raises():
    with pytest.raises(InvalidPrivateKeyError):
        PrivateKey(-1)
    with pytest.raises(InvalidPrivateKeyError):
        PrivateKey(0)
    with pytest.raises(InvalidPrivateKeyError):
        PrivateKey(utils.CURVE.order)


def test_invalid_peer_public_key_raises():
    private_a, _ = ecdh_generate_keys()
    with pytest.raises(InvalidPublicKeyError):
        ecdh_shared_secret(private_a, PublicKey(1, 1))


def test_malformed_public_key_fields_raise():
    with pytest.raises(InvalidPublicKeyError):
        PublicKey("x", "y")  # type: ignore[arg-type]
    with pytest.raises(InvalidPublicKeyError):
        PublicKey(-1, 0)
    with pytest.raises(InvalidPublicKeyError):
        PublicKey(2**utils.CURVE.degree, 0)


def test_private_key_repr_and_str_do_not_leak_scalar():
    private_key, _ = ecdh_generate_keys()
    assert str(private_key.scalar) not in repr(private_key)
    assert str(private_key.scalar) not in str(private_key)


def test_validate_public_key_point_is_callable_independently():
    base_x, base_y = utils.CURVE.base_x, utils.CURVE.base_y
    validate_public_key_point(base_x, base_y)
    with pytest.raises(PublicKeyPointAtInfinityError):
        validate_public_key_point(0, 0)


def test_point_at_infinity_is_rejected():
    with pytest.raises(PublicKeyPointAtInfinityError):
        PublicKey(0, 0)


def test_off_curve_point_with_in_range_coordinates_is_rejected():
    with pytest.raises(PublicKeyNotOnCurveError):
        PublicKey(1, 1)


def test_coordinates_outside_the_field_are_rejected_not_reduced():
    with pytest.raises(PublicKeyCoordinateRangeError):
        PublicKey(-1, 0)
    with pytest.raises(PublicKeyCoordinateRangeError):
        PublicKey(2**utils.CURVE.degree, 0)


def test_small_order_point_passes_old_checks_but_fails_subgroup_check():
    x, y = 0, _SMALL_ORDER_Y
    assert not utils.gf2point_is_zero(x, y)
    assert utils.gf2point_on_curve(x, y)
    with pytest.raises(PublicKeyNotInSubgroupError):
        PublicKey(x, y)


def test_unvalidated_peer_key_is_rejected_by_the_shared_secret_gate():
    private_a, _ = ecdh_generate_keys()
    peer_of_order_two = PublicKey.__new__(PublicKey)
    object.__setattr__(peer_of_order_two, "x", 0)
    object.__setattr__(peer_of_order_two, "y", _SMALL_ORDER_Y)
    with pytest.raises(PublicKeyNotInSubgroupError):
        ecdh_shared_secret(private_a, peer_of_order_two)


def test_shared_secret_at_infinity_is_rejected_not_returned(monkeypatch):
    from tiny_ecdh import InvalidSharedSecretError, ecdh

    monkeypatch.setattr(ecdh, "validate_public_key_point", lambda x, y: None)
    peer_of_order_two = PublicKey.__new__(PublicKey)
    object.__setattr__(peer_of_order_two, "x", 0)
    object.__setattr__(peer_of_order_two, "y", _SMALL_ORDER_Y)
    with pytest.raises(InvalidSharedSecretError):
        ecdh_shared_secret(PrivateKey(2), peer_of_order_two)
