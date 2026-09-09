# Tiny ECDH in Python

> ## ⚠️ Educational only — do not use in production
>
> This package exists to demonstrate how Elliptic-Curve Diffie–Hellman is put together.
> It is **not** production cryptography and must never be shipped as such:
>
> - **~80-bit curve strength.** The curve is sect163r2 (NIST B-163), far below the
>   112-bit floor any current guidance requires.
> - **Withdrawn curve.** Binary-field curves are no longer approved by NIST
>   (FIPS 186-5, SP 800-186) and sect163r2 was dropped from SEC 2 v2.0.
> - **Timing side channels.** The pure-Python field arithmetic cannot be made
>   timing-uniform; secret-dependent timing is present and documented, not fixed.
> - **No zeroisation.** Secret material is never wiped from memory.
> - **No independent review.** No audit, no formal analysis.
>
> For real key agreement use an audited library:
> [`cryptography`](https://cryptography.io/) (`cryptography.hazmat.primitives.asymmetric.x25519`)
> or [PyNaCl](https://pynacl.readthedocs.io/).

## What this is

A Python port of [kokke/tiny-ECDH-c](https://github.com/kokke/tiny-ECDH-c), a small
implementation of the
[Elliptic-Curve Diffie–Hellman key agreement algorithm](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman).
The code follows the C original closely rather than being idiomatic Python, and it is
much slower than the C version.

> Elliptic-curve Diffie–Hellman (ECDH) is an anonymous key agreement protocol that allows two parties, each having an elliptic-curve public–private key pair, to establish a shared secret over an insecure channel.

### The curve

The implemented curve is **sect163r2**, also published as **NIST B-163**: a pseudo-random
(not Koblitz) curve over the binary field GF(2^163). Its parameters are taken from
[SEC 2: Recommended Elliptic Curve Domain Parameters, Version 1.0](https://www.secg.org/SEC2-Ver-1.0.pdf)
(§3.7.2), consistent with FIPS 186-4 Appendix D. They are pinned by
`tests/test_curve_parameters.py`.

The curve offers roughly 80 bits of security. It has since been withdrawn: FIPS 186-5
and NIST SP 800-186 no longer approve binary or Koblitz curves, and SEC 2 Version 2.0
removed the 163-bit curves entirely.

### Attribution and licence

This is a derivative work of [kokke/tiny-ECDH-c](https://github.com/kokke/tiny-ECDH-c),
which is released into the public domain under the [Unlicense](https://unlicense.org/).
Public-domain dedication imposes no conditions, so redistributing this port under the
MIT [`LICENSE`](LICENSE) is compatible. Curve parameters are from SEC 2 / FIPS 186-4 as
cited above.

## Suggested reading order

The package is meant to be read. A useful path through it:

1. `tiny_ecdh/utils.py` — the curve definition and GF(2^m) field and point arithmetic
   (`gf2field_*`, `gf2point_*`), including the branch-free point operations.
2. `tiny_ecdh/keys.py` — the `PrivateKey`, `PublicKey` and `SharedSecret` types and the
   validation a peer key must pass.
3. `tiny_ecdh/entropy.py` — how the private scalar is drawn from OS entropy.
4. `tiny_ecdh/ecdh.py` — the two entry points, `ecdh_generate_keys` and
   `ecdh_shared_secret`, tied together from the pieces above.
5. `tiny_ecdh/kdf.py` — turning the shared point's x-coordinate into a usable key.
6. `examples/ecdh_example.py` — a full exchange end to end.
7. `tests/` — known-answer vectors and property tests, sourced independently of this
   implementation.

## Usage

Install with `pip install tiny-ecdh-python` and import from `tiny_ecdh`:

```python
from tiny_ecdh import ecdh_generate_keys, ecdh_shared_secret
```

The point that comes out of the exchange is **not** a key: its bits carry the algebraic
structure of the curve equation, not uniform randomness. Always derive a key from it, as
below.

1. Alice and Bob each generate a key pair. The private scalar is drawn from the
   operating system's entropy source; the result is typed `PrivateKey` / `PublicKey`.

```python
alice_priv, alice_pub = ecdh_generate_keys()
bob_priv, bob_pub = ecdh_generate_keys()
```

2. They exchange public keys over the insecure channel.

3. Each side computes the shared point and derives a key from it, bound to a context
   string that names what the key is for:

```python
from tiny_ecdh import constant_time_compare

context = b"my-app: session key v1"

# raises InvalidPublicKeyError if the peer key fails validation
alice_key = ecdh_shared_secret(alice_priv, bob_pub).derive_key(context)
bob_key = ecdh_shared_secret(bob_priv, alice_pub).derive_key(context)
```

4. Both sides now hold the same fixed-length derived key. Compare derived keys in
   constant time, never with `==`:

```python
assert constant_time_compare(alice_key, bob_key)
```

A different `context` on the same key pair yields a completely different key, so one pair
can serve independent purposes without them sharing key material. The shared point's
x-coordinate is available as `SharedSecret.raw_x` for comparison against the C original;
it is deliberately named so that reading it instead of calling `derive_key` is a visible
decision, not the normal path.

Deriving the key does not authenticate *who* you share it with: ECDH here is
unauthenticated, so a peer key could belong to an impersonator. Verify the peer's public
key and the handshake transcript through some other channel (a signature, a certificate,
an out-of-band fingerprint) before trusting a derived key.

## Timing limitations

Scalar multiplication always runs the same fixed number of double-and-add-always
iterations, and each iteration performs the same sequence of point operations regardless
of the scalar: point doubling and addition use branch-free variants that always compute
every case and select the result arithmetically. So the implementation no longer leaks
the scalar's bit length through the iteration count, or the position of coincidences
between the running total and the added point through which case is taken. This is a
fixed *schedule of point operations*, not constant-time execution, and the package must
not be described that way — several point operations are still data-dependent underneath:

- Field inversion (`gf2field_inv`) is variable-time extended-Euclid; its running time
  depends on the element being inverted, and it runs three times per iteration.
- Field multiplication (`gf2field_mul`) loops once per bit of one operand and branches on
  each bit, so both its iteration count and branch choice depend on an operand derived
  from the secret scalar.
- Python's arbitrary-precision integers do not run in fixed time for a fixed bit width.
  This cannot be closed from pure Python.

See [SECURITY.md](SECURITY.md) for the full threat model and the list of known,
accepted weaknesses.

## Development checks

Run the complete local gate with:

```sh
python -m pip install tox
python -m tox
```

This runs the test suite on Python 3.9–3.12 and, in the quality environment, checks
linting, formatting, the source and wheel builds, and artifact metadata.
