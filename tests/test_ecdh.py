import numpy as np

from tiny_ecdh import ecdh_generate_keys, ecdh_shared_secret

MIN_NUMPY = (1, 24)
MAX_NUMPY = (3,)


def _numpy_version_tuple():
    return tuple(int(part) for part in np.__version__.split(".")[:2])


def test_numpy_version_is_within_declared_support_range():
    version = _numpy_version_tuple()
    assert version >= MIN_NUMPY
    assert version < MAX_NUMPY


def _random_private_key():
    private = np.zeros(6, dtype="u4")
    for i in range(6):
        private[i] = np.random.randint(4294967296, dtype=np.uint32)
    return private


def _generate_keypair():
    private = _random_private_key()
    public = np.zeros(12, dtype="u4")
    private, public = ecdh_generate_keys(private, public)
    assert private is not None
    assert public is not None
    return private, public


def test_generate_keys_succeeds_on_current_numpy():
    private, public = _generate_keypair()
    assert private.dtype == np.uint32
    assert public.dtype == np.uint32


def test_shared_secret_derivation_is_repeatable_and_inputs_are_unchanged():
    private_a, public_a = _generate_keypair()
    private_b, public_b = _generate_keypair()

    public_a_before = public_a.copy()
    public_b_before = public_b.copy()
    private_a_before = private_a.copy()
    private_b_before = private_b.copy()

    secret_a_first = ecdh_shared_secret(private_a, public_b)
    secret_a_second = ecdh_shared_secret(private_a, public_b)

    assert np.array_equal(secret_a_first, secret_a_second)
    assert np.array_equal(public_a, public_a_before)
    assert np.array_equal(public_b, public_b_before)
    assert np.array_equal(private_a, private_a_before)
    assert np.array_equal(private_b, private_b_before)


def test_both_parties_derive_the_same_shared_secret():
    private_a, public_a = _generate_keypair()
    private_b, public_b = _generate_keypair()

    secret_a = ecdh_shared_secret(private_a, public_b)
    secret_b = ecdh_shared_secret(private_b, public_a)

    assert secret_a is not None
    assert secret_b is not None
    assert np.array_equal(secret_a, secret_b), "parties disagree on the shared secret"
