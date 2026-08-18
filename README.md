### Tiny ECDH in Python

Install the educational package with `pip install tiny-ecdh-python` and import its public API
from `tiny_ecdh`:

```Python
from tiny_ecdh import ecdh_generate_keys, ecdh_shared_secret
```

This is a Python implementation of the [Tiny ECDH in C](https://github.com/kokke/tiny-ECDH-c) 

It's a small and portable implementation of the [Elliptic-Curve Diffie-Hellman key agreement algorithm](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman) written in Python.

Description from Wikipedia:

> Elliptic-curve Diffie–Hellman (ECDH) is an anonymous key agreement protocol that allows two parties, each having an elliptic-curve public–private key pair, to establish a shared secret over an insecure channel. It is a variant of the Diffie–Hellman protocol using elliptic-curve cryptography.

The raw curve point that comes out of the exchange is **not** a key: its bits carry the
algebraic structure of the curve equation, not uniform randomness. Never use it directly to
encrypt anything -- always derive a key from it first, as shown below.

This repository was developed just by replicating the C version in Python, and can be improved to a more pythonic alternative. It's still very slow when compared to the C version.

Usage:

The [ECDH algorithm](https://cryptobook.nakov.com/asymmetric-key-ciphers/ecdh-key-exchange)  (Elliptic Curve Diffie–Hellman Key Exchange) is trivial:

1. Alice generates a random ECC key pair: {alicePrivKey, alicePubKey = alicePrivKey * G}
```Python
# draws the private scalar from the operating system's entropy source;
# returns typed PrivateKey/PublicKey objects
alicePrivKey, alicePubKey = ecdh_generate_keys()
```
2. Bob generates a random ECC key pair: {bobPrivKey, bobPubKey = bobPrivKey * G}
```Python
bobPrivKey, bobPubKey = ecdh_generate_keys()
```
3. Alice and Bob exchange their public keys through the insecure channel (e.g. over Bluetooth)

4. Alice calculates the shared point and derives a key from it, bound to a context that names
   what the key is for:
```Python
from tiny_ecdh import constant_time_compare

context = b"my-app: session key v1"

# raises InvalidPublicKeyError if bobPubKey fails validation
aliceSharedPoint = ecdh_shared_secret(alicePrivKey, bobPubKey)
aliceKey = aliceSharedPoint.derive_key(context)
```

5. Bob does the same with the same context:
```Python
bobSharedPoint = ecdh_shared_secret(bobPrivKey, alicePubKey)
bobKey = bobSharedPoint.derive_key(context)
```

6. Now both Alice and Bob have the same fixed-length, uniformly distributed key, safe to use
   directly with a symmetric cipher. Compare derived keys in constant time, never with `==`:

```Python
assert constant_time_compare(aliceKey, bobKey)
```

A different `context` value on the same key pair produces a completely different key, so the
same pair can be reused safely across independent purposes without those purposes sharing key
material. `aliceSharedPoint.raw_x` is the undifferentiated x-coordinate of the shared point; it
is kept only for teaching value and comparison against the original C implementation, and is
deliberately named so that reading it instead of calling `derive_key` is a visible decision, not
the normal path.

### Timing limitations

Scalar multiplication always runs the same fixed number of double-and-add-always
iterations, and each iteration always performs the same sequence of point
operations regardless of the scalar: point doubling and addition are built from
branch-free variants that always compute every case (identity operand, the
doubling case, points summing to the identity, the general case) and select the
right result arithmetically, instead of branching to a cheaper or more expensive
path. So the implementation no longer leaks the scalar's bit length through the
iteration count, or the position of any coincidence between the running total
and the point being added through which top-level case is taken. This is a
fixed *schedule of point operations*, not constant-time execution, and the
package must not be described that way — several of those point operations are
themselves still data-dependent underneath:

- Field inversion (`gf2field_inv`) is still variable-time extended-Euclid; its
  running time depends on the field element being inverted, and it runs three
  times per iteration, always, but each call's own running time still varies
  with its input. Fixing this is tracked separately.
- Field multiplication (`gf2field_mul`) loops once per bit of one operand and
  branches on each bit (`while y: ... if y & 1`), so both its iteration count
  and which branch it takes on a given iteration depend on the operand's bit
  pattern — which, inside the ladder, is derived from the secret scalar. This
  is the same class of leak as field inversion and is not fixed by the
  branch-free point operations above.
- Python's arbitrary-precision integers do not execute in fixed time for a
  fixed bit width — operations on operands of different magnitude take
  different amounts of interpreter time regardless of how the algorithm above
  is shaped. This cannot be closed from pure Python.

### TODO:

- Add more NIST curves
- Create a more pythonic alternative
# Development checks

Run the complete local gate with:

```sh
python -m pip install tox
python -m tox
```

This runs the test suite on Python 3.9–3.12 and, in the quality environment, checks linting,
formatting, the source and wheel builds, and artifact metadata.
