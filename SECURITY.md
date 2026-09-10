# Security policy

`tiny-ecdh-python` is an **educational** package. It demonstrates how Elliptic-Curve
Diffie–Hellman is constructed. It is not fit for protecting real data and is not
maintained as if it were. Nothing below should be read as a claim that the package can be
made production-ready.

## Threat model

The package is intended for one use: reading and running it to learn how ECDH works, on a
machine the reader controls, with no adversary present.

It is **out of scope** to defend against:

- an attacker who can measure execution time, cache behaviour, or other microarchitectural
  side effects of a key operation (timing side channels — see below);
- an attacker who can read process memory, core dumps, or swap (no secret zeroisation);
- an attacker with the computational budget to attack an ~80-bit curve;
- an active attacker on the channel (ECDH here is unauthenticated — a peer public key may
  belong to an impersonator; authentication must be layered on top);
- any use of the raw shared point as key material instead of `SharedSecret.derive_key`.

## Known and accepted weaknesses

These are properties of the design, known and deliberately not mitigated. They are
documented, not tracked as vulnerabilities:

- **Curve strength.** sect163r2 / NIST B-163 provides roughly 80 bits of security, below
  the 112-bit minimum of current guidance.
- **Deprecated curve.** NIST SP 800-186 still specifies the binary-field curves but
  marks them deprecated for new use. sect163r2 remains in SEC 2 v2.0 (§3.2.3).
- **Timing side channels.** Scalar multiplication runs a fixed schedule of point
  operations, but field inversion and field multiplication remain data-dependent, and
  CPython's big integers are not fixed-time for a fixed bit width. Secret-dependent
  timing is present and cannot be removed in pure Python. This is documented behaviour,
  not a bug to report.
- **No memory zeroisation.** Private scalars and derived keys are ordinary Python objects
  and are not wiped; copies may persist in memory, swap, or dumps.
- **No independent review.** The implementation has had no audit or formal analysis.
- **Unauthenticated key agreement.** No identity binding; callers must authenticate peers
  and transcripts by other means.
- **Performance.** The implementation is a direct port of a C original and is slow; it
  makes no constant-time or hardened-arithmetic guarantees.

## Reporting a correctness bug

A genuine **correctness** bug — the exchange producing mismatched keys, a valid peer key
rejected, an invalid one accepted, curve parameters not matching SEC 2 / FIPS 186-4,
a crash on supported input — is worth reporting.

Open an issue at
<https://github.com/danielsousaoliveira/tiny-ECDH-python/issues> with a minimal
reproduction and the observed versus expected result.

Timing variation, the curve's low strength, lack of zeroisation, and the other items
under "Known and accepted weaknesses" are not correctness bugs and are already documented
here.
