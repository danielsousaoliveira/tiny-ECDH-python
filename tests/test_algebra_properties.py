"""Property-based tests for the field and curve arithmetic.

Hypothesis reports the exact failing input (and shrinks it to a minimal
counterexample) whenever a property breaks, so a failure here is always
reproducible rather than a one-off mystery value.
"""

from hypothesis import given, settings
from hypothesis import strategies as st

from tiny_ecdh import PrivateKey, PublicKey, ecdh_shared_secret, utils

_field_elements = st.integers(min_value=0, max_value=2**utils.CURVE.degree - 1)
_nonzero_field_elements = st.integers(min_value=1, max_value=2**utils.CURVE.degree - 1)
_scalars = st.integers(min_value=1, max_value=utils.CURVE.order - 1)

_G = (utils.CURVE.base_x, utils.CURVE.base_y)

#: The constant-time double-and-add-always ladder (see DAN-55) always runs
#: CURVE.degree iterations regardless of the scalar, so every scalar
#: multiplication is slow by design; give these examples room accordingly.
_scalar_mul_settings = settings(deadline=None, max_examples=25)


@given(_field_elements, _field_elements)
def test_field_addition_is_commutative(a, b):
    assert utils.gf2field_add(a, b) == utils.gf2field_add(b, a)


@given(_field_elements, _field_elements, _field_elements)
def test_field_addition_is_associative(a, b, c):
    assert utils.gf2field_add(utils.gf2field_add(a, b), c) == utils.gf2field_add(
        a, utils.gf2field_add(b, c)
    )


@given(_field_elements)
def test_field_addition_has_identity_and_self_inverse(a):
    assert utils.gf2field_add(a, 0) == a
    assert utils.gf2field_add(a, a) == 0


@given(_field_elements, _field_elements)
def test_field_multiplication_is_commutative(a, b):
    assert utils.gf2field_mul(a, b) == utils.gf2field_mul(b, a)


@given(_field_elements, _field_elements, _field_elements)
def test_field_multiplication_is_associative(a, b, c):
    assert utils.gf2field_mul(utils.gf2field_mul(a, b), c) == utils.gf2field_mul(
        a, utils.gf2field_mul(b, c)
    )


@given(_field_elements, _field_elements, _field_elements)
def test_field_multiplication_distributes_over_addition(a, b, c):
    assert utils.gf2field_mul(a, utils.gf2field_add(b, c)) == utils.gf2field_add(
        utils.gf2field_mul(a, b), utils.gf2field_mul(a, c)
    )


@given(_field_elements)
def test_field_multiplication_has_identity(a):
    assert utils.gf2field_mul(a, 1) == a


@given(_nonzero_field_elements)
def test_field_multiplicative_inverse(a):
    assert utils.gf2field_mul(a, utils.gf2field_inv(a)) == 1


@_scalar_mul_settings
@given(_scalars)
def test_doubling_agrees_with_adding_a_point_to_itself(k):
    point = utils.gf2point_mul(*_G, k)
    if utils.gf2point_is_zero(*point):
        return
    assert utils.gf2point_double(*point) == utils.gf2point_add(*point, *point)


@given(st.integers(min_value=1, max_value=20))
def test_repeated_addition_agrees_with_scalar_multiplication(n):
    accumulated = utils.gf2point_set_zero()
    for _ in range(n):
        accumulated = utils.gf2point_add(*accumulated, *_G)
    assert accumulated == utils.gf2point_mul(*_G, n)


@_scalar_mul_settings
@given(_scalars, _scalars)
def test_sequential_scalar_multiplication_agrees_with_the_product(j, k):
    by_product = utils.gf2point_mul(*_G, (j * k) % utils.CURVE.order)
    sequential = utils.gf2point_mul(*utils.gf2point_mul(*_G, j), k)
    assert by_product == sequential


@_scalar_mul_settings
@given(_scalars, _scalars)
def test_both_parties_derive_the_same_shared_secret(a_scalar, b_scalar):
    private_a = PrivateKey(a_scalar)
    private_b = PrivateKey(b_scalar)
    public_a = PublicKey(*utils.gf2point_mul(*_G, a_scalar))
    public_b = PublicKey(*utils.gf2point_mul(*_G, b_scalar))
    secret_a = ecdh_shared_secret(private_a, public_b)
    secret_b = ecdh_shared_secret(private_b, public_a)
    assert secret_a == secret_b
