"""Run a small educational B-163 ECDH exchange."""

import secrets

from tiny_ecdh import ecdh_generate_keys, ecdh_shared_secret
from tiny_ecdh.utils import CURVE


def main():
    minimum = 2**80
    alice_private, alice_public = ecdh_generate_keys(
        minimum + secrets.randbelow(CURVE.order - minimum)
    )
    bob_private, bob_public = ecdh_generate_keys(
        minimum + secrets.randbelow(CURVE.order - minimum)
    )
    alice_secret = ecdh_shared_secret(alice_private, bob_public)
    bob_secret = ecdh_shared_secret(bob_private, alice_public)
    print("Equal Key" if alice_secret == bob_secret else "Error: Key Not Equal")


if __name__ == "__main__":
    main()
