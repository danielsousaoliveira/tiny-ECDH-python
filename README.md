### Tiny ECDH in Python

Install the educational package with `pip install tiny-ecdh-python` and import its public API
from `tiny_ecdh`:

```Python
from tiny_ecdh import ecdh_generate_keys, ecdh_shared_secret
```

This is a Python implementation of the [Tiny ECDH in C](https://github.com/kokke/tiny-ECDH-c) 

It's a small and portable implementation of the [Elliptic-Curve Diffie-Hellman key agreement algorithm](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman) written in Python.

Description from Wikipedia:

> Elliptic-curve Diffie–Hellman (ECDH) is an anonymous key agreement protocol that allows two parties, each having an elliptic-curve public–private key pair, to establish a shared secret over an insecure channel. This shared secret may be directly used as a key, or to derive another key. The key, or the derived key, can then be used to encrypt subsequent communications using a symmetric-key cipher. It is a variant of the Diffie–Hellman protocol using elliptic-curve cryptography.
`
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

4. Alice calculates sharedKey = bobPubKey * alicePrivKey
```Python
# raises InvalidPublicKeyError if bobPubKey fails validation
aliceSharedKey = ecdh_shared_secret(alicePrivKey, bobPubKey)
```

5. Bob calculates sharedKey = alicePubKey * bobPrivKey
```Python
bobSharedKey = ecdh_shared_secret(bobPrivKey, alicePubKey)
```

6. Now both Alice and Bob have the same sharedKey == bobPubKey * alicePrivKey == alicePubKey * bobPrivKey

```Python
assert aliceSharedKey == bobSharedKey
```

### Timing limitations

Scalar multiplication always runs the same fixed number of double-and-add-always
iterations, and each iteration always performs the same field operations in the
same order regardless of the scalar: point doubling and addition are built from
branch-free variants that always compute every case (identity operand, the
doubling case, points summing to the identity, the general case) and select the
right result arithmetically, instead of branching to a cheaper or more expensive
path. So the implementation no longer leaks the scalar's bit length, Hamming
weight, or the position of any coincidence between the running total and the
point being added. This is not the same as constant-time, and the package must
not be described that way:

- Field inversion (`gf2field_inv`) is still variable-time extended-Euclid; its
  running time depends on the field element being inverted, and it is called
  from every point doubling and addition — twice per iteration, always, but
  each call's own running time still varies with its input. Fixing this is
  tracked separately.
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
