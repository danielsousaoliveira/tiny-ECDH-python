"""Run a small educational B-163 ECDH exchange.

Educational code only. See the README and SECURITY.md before reading further:
this curve offers roughly 80-bit strength and is deprecated for new use, and the
pure-Python arithmetic cannot be made timing-uniform.
"""

from tiny_ecdh import constant_time_compare, ecdh_generate_keys, ecdh_shared_secret

_CONTEXT = b"tiny-ecdh-example v1"


def main():
    alice_private, alice_public = ecdh_generate_keys()
    bob_private, bob_public = ecdh_generate_keys()
    alice_key = ecdh_shared_secret(alice_private, bob_public).derive_key(_CONTEXT)
    bob_key = ecdh_shared_secret(bob_private, alice_public).derive_key(_CONTEXT)
    if not constant_time_compare(alice_key, bob_key):
        raise SystemExit("derived keys differ")
    print("derived keys match")


if __name__ == "__main__":
    main()
