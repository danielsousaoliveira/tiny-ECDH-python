"""Post-install smoke test: full ECDH exchange using only the installed package.

Run against an interpreter that has ``tiny-ecdh-python`` installed and nothing
from this source tree on ``sys.path``. Pass the expected version (the release
tag without its leading ``v``) as the first argument to assert that the
installed package reports it.

    python scripts/smoke_test.py 0.1.0a1
"""

import sys
from pathlib import Path

if Path.cwd() == Path(__file__).resolve().parent.parent:
    sys.exit(
        "run this from outside the source tree so the installed package is imported"
    )

import tiny_ecdh
from tiny_ecdh import (
    constant_time_compare,
    ecdh_generate_keys,
    ecdh_shared_secret,
)

_CONTEXT = b"tiny-ecdh smoke test"


def main() -> None:
    if len(sys.argv) > 1:
        expected = sys.argv[1]
        if tiny_ecdh.__version__ != expected:
            sys.exit(
                f"version mismatch: installed {tiny_ecdh.__version__!r}, expected {expected!r}"
            )

    alice_private, alice_public = ecdh_generate_keys()
    bob_private, bob_public = ecdh_generate_keys()

    alice_key = ecdh_shared_secret(alice_private, bob_public).derive_key(_CONTEXT)
    bob_key = ecdh_shared_secret(bob_private, alice_public).derive_key(_CONTEXT)

    if not constant_time_compare(alice_key, bob_key):
        sys.exit("derived keys differ")
    if len(alice_key) == 0:
        sys.exit("derived key is empty")

    print(f"ok: tiny-ecdh-python {tiny_ecdh.__version__} completed a full key exchange")


if __name__ == "__main__":
    main()
