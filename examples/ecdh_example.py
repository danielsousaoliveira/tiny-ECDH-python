"""Run a small educational B-163 ECDH exchange."""

from tiny_ecdh import ecdh_generate_keys, ecdh_shared_secret


def main():
    alice_private, alice_public = ecdh_generate_keys()
    bob_private, bob_public = ecdh_generate_keys()
    alice_secret = ecdh_shared_secret(alice_private, bob_public)
    bob_secret = ecdh_shared_secret(bob_private, alice_public)
    print("Equal Key" if alice_secret == bob_secret else "Error: Key Not Equal")


if __name__ == "__main__":
    main()
