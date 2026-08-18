import pytest

from tiny_ecdh import (
    InvalidPrivateKeyError,
    InvalidPublicKeyError,
    PrivateKey,
    PublicKey,
    ecdh_generate_keys,
    ecdh_shared_secret,
    utils,
)


def test_key_exchange_and_immutable_inputs():
    private_a, public_a = ecdh_generate_keys(utils.CURVE.order // 3)
    private_b, public_b = ecdh_generate_keys(utils.CURVE.order // 5)
    assert isinstance(private_a, PrivateKey)
    assert isinstance(public_a, PublicKey)
    public_b_before = public_b
    secret_a = ecdh_shared_secret(private_a, public_b)
    secret_b = ecdh_shared_secret(private_b, public_a)
    assert secret_a == secret_b
    assert public_b == public_b_before


def test_private_key_below_minimum_raises():
    with pytest.raises(InvalidPrivateKeyError):
        ecdh_generate_keys(1)


def test_private_key_negative_scalar_raises():
    with pytest.raises(InvalidPrivateKeyError):
        ecdh_generate_keys(-1)


def test_private_key_at_or_above_curve_order_raises():
    with pytest.raises(InvalidPrivateKeyError):
        ecdh_generate_keys(utils.CURVE.order)
    with pytest.raises(InvalidPrivateKeyError):
        ecdh_generate_keys(utils.CURVE.order + 2**80)


def test_manually_constructed_private_key_out_of_range_raises():
    with pytest.raises(InvalidPrivateKeyError):
        PrivateKey(-1)
    with pytest.raises(InvalidPrivateKeyError):
        PrivateKey(0)
    with pytest.raises(InvalidPrivateKeyError):
        PrivateKey(utils.CURVE.order)


def test_invalid_peer_public_key_raises():
    private_a, _ = ecdh_generate_keys(utils.CURVE.order // 3)
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
    private_key, _ = ecdh_generate_keys(utils.CURVE.order // 3)
    assert str(private_key.scalar) not in repr(private_key)
    assert str(private_key.scalar) not in str(private_key)
