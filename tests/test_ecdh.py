from tiny_ecdh import ecdh_generate_keys, ecdh_shared_secret
from tiny_ecdh import utils


def test_key_exchange_and_immutable_inputs():
    private_a, public_a = ecdh_generate_keys(utils.CURVE.order // 3)
    private_b, public_b = ecdh_generate_keys(utils.CURVE.order // 5)
    assert private_a and private_b
    public_b_before = public_b
    secret_a = ecdh_shared_secret(private_a, public_b)
    secret_b = ecdh_shared_secret(private_b, public_a)
    assert secret_a == secret_b
    assert public_b == public_b_before
