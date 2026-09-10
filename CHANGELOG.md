# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[PEP 440](https://peps.python.org/pep-0440/).

> **The public interface is not stable.** This project is pre-1.0 and released
> for education. Names, signatures, error types, and the shared-secret format
> may change in any release without a deprecation period until 1.0.0.

## [Unreleased]

## [0.1.0a1] - 2026-09-10

First release to the Python Package Index. Alpha: published to reserve the name
and exercise the release path, not to signal a stable interface.

This is the first tagged version, so the entries below describe the shape the
interface reached on the way here rather than changes against a previous
release.

### Packaging

- Distributed as the `tiny_ecdh` import package (the earlier flat `ecdh` and
  `utils` top-level modules are gone).
- Ships `py.typed`; the public surface is type-hinted.
- Single version source: `tiny_ecdh/_version.py`, exposed as
  `tiny_ecdh.__version__` and as the distribution version via a dynamic
  `pyproject.toml` field.
- Runs on numpy 1.x and numpy 2.x (the earlier `OverflowError` in
  `bitvec_clr_bit` on numpy >= 2 is fixed).
- Published from a tag by a GitHub Actions workflow using PyPI Trusted
  Publishing (OIDC, no stored token) with PEP 740 build provenance. The sdist
  and wheel are byte-reproducible from the tag with the pinned build toolchain
  in `requirements/build.txt`; CI rebuilds and compares hashes on every release.

### Interface

- Keys and secrets are typed objects, not bare tuples: `PrivateKey`,
  `PublicKey`, `SharedSecret`. Fields are validated at construction.
- Typed error hierarchy rooted at `TinyECDHError`
  (`InvalidPrivateKeyError`, `InvalidPublicKeyError`, `InvalidSharedSecretError`,
  `PublicKeyCoordinateRangeError`, `PublicKeyNotOnCurveError`,
  `PublicKeyPointAtInfinityError`, `PublicKeyNotInSubgroupError`).
- `ecdh_generate_keys()` draws the private scalar from the operating system
  CSPRNG. It no longer accepts a caller-supplied or seedable RNG; tests inject a
  named `entropy_source` only.
- `PublicKey` construction rejects points that are not on the curve, are the
  point at infinity, or are outside the base-point subgroup, each with a
  distinct error type.
- Fixed-width `bytes`/`hex` encoding and decoding for keys, with
  `FIELD_BYTE_LENGTH`, `PRIVATE_KEY_BYTE_LENGTH`, `PUBLIC_KEY_BYTE_LENGTH`.
- Scalar multiplication runs a fixed number of steps per scalar bit-length.

### Shared-secret format (changed)

- `ecdh_shared_secret(private_key, peer_public_key)` returns a `SharedSecret`
  wrapping the agreed point's x-coordinate. It no longer returns, or writes
  back into the caller's array, the raw unhashed `x || y` bytes, and it no
  longer mutates the peer's public key.
- Key material must be derived explicitly: `SharedSecret.derive_key(context)`
  applies a KDF over the x-coordinate and returns a fixed-length key.
  `DEFAULT_SHARED_KEY_LENGTH` and `constant_time_compare` are exported for
  callers. **This format is not covered by any stability guarantee and may
  change before 1.0.0.**

### Known limitations (unchanged, by design)

- ~80-bit curve strength (sect163r2 / NIST B-163), below every current
  minimum; the curve is deprecated for new use.
- Secret-dependent timing in the pure-Python field arithmetic is present and
  documented, not eliminated.
- No zeroisation of secret material. No independent review.

[Unreleased]: https://github.com/danielsousaoliveira/tiny-ECDH-python/compare/v0.1.0a1...HEAD
[0.1.0a1]: https://github.com/danielsousaoliveira/tiny-ECDH-python/releases/tag/v0.1.0a1
