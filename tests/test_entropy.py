from tiny_ecdh import ecdh_generate_keys
from tiny_ecdh.entropy import default_entropy_source, random_scalar
from tiny_ecdh.utils import CURVE

_BYTE_LENGTH = (CURVE.order.bit_length() + 7) // 8


def _fixed_bytes(*values: int):
    queue = list(values)

    def source(n: int) -> bytes:
        return queue.pop(0).to_bytes(n, "big")

    return source


def test_zero_and_out_of_range_draws_are_rejected_and_redrawn():
    zero = 0
    out_of_range = CURVE.order
    valid = CURVE.order // 3
    source = _fixed_bytes(zero, out_of_range, valid)
    assert random_scalar(entropy_source=source) == valid


def test_scalar_is_never_zero():
    source = _fixed_bytes(0, 1)
    assert random_scalar(entropy_source=source) == 1


def test_default_entropy_source_is_not_seedable_globally():
    import random as pyrandom

    pyrandom.seed(0)
    first = ecdh_generate_keys()[0].scalar
    pyrandom.seed(0)
    second = ecdh_generate_keys()[0].scalar
    assert first != second


def test_high_bit_shows_no_bias_over_many_draws():
    top_bit = CURVE.order.bit_length() - 1
    draws = [random_scalar() for _ in range(500)]
    set_count = sum(1 for scalar in draws if (scalar >> (top_bit - 1)) & 1)
    assert 150 < set_count < 350


def test_generated_scalars_are_within_valid_range():
    for _ in range(50):
        private_key, _ = ecdh_generate_keys()
        assert 1 <= private_key.scalar < CURVE.order


def test_default_entropy_source_is_secrets_token_bytes():
    import secrets

    assert default_entropy_source is secrets.token_bytes
