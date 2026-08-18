import pytest

from tiny_ecdh import (
    DEFAULT_SHARED_KEY_LENGTH,
    constant_time_compare,
    ecdh_generate_keys,
    ecdh_shared_secret,
)
from tiny_ecdh.kdf import derive_shared_key


def test_both_parties_derive_the_same_fixed_length_key():
    private_a, public_a = ecdh_generate_keys()
    private_b, public_b = ecdh_generate_keys()
    secret_a = ecdh_shared_secret(private_a, public_b)
    secret_b = ecdh_shared_secret(private_b, public_a)

    key_a = secret_a.derive_key(b"purpose")
    key_b = secret_b.derive_key(b"purpose")

    assert key_a == key_b
    assert len(key_a) == DEFAULT_SHARED_KEY_LENGTH
    assert key_a != secret_a.raw_x.to_bytes(
        (secret_a.raw_x.bit_length() + 7) // 8 or 1, "big"
    )


def test_derived_key_depends_on_context():
    private_a, _ = ecdh_generate_keys()
    _, public_b = ecdh_generate_keys()
    secret = ecdh_shared_secret(private_a, public_b)

    key_one = secret.derive_key(b"purpose-one")
    key_two = secret.derive_key(b"purpose-two")

    assert key_one != key_two


def test_derived_key_length_is_configurable_and_field_independent():
    private_a, _ = ecdh_generate_keys()
    _, public_b = ecdh_generate_keys()
    secret = ecdh_shared_secret(private_a, public_b)

    assert len(secret.derive_key(b"ctx", length=16)) == 16
    assert len(secret.derive_key(b"ctx", length=64)) == 64


def test_derive_shared_key_rejects_non_positive_length():
    with pytest.raises(ValueError):
        derive_shared_key(1, 21, b"ctx", length=0)


def test_derive_shared_key_rejects_non_bytes_context():
    with pytest.raises(TypeError):
        derive_shared_key(1, 21, "not-bytes")  # type: ignore[arg-type]


def test_constant_time_compare_matches_and_mismatches():
    assert constant_time_compare(b"abc", b"abc")
    assert not constant_time_compare(b"abc", b"abd")
    assert not constant_time_compare(b"abc", b"abcd")


def test_constant_time_compare_rejects_non_bytes():
    with pytest.raises(TypeError):
        constant_time_compare("abc", "abc")  # type: ignore[arg-type]
