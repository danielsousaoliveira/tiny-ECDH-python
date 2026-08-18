"""Run a small educational B-163 ECDH exchange."""

from tiny_ecdh import constant_time_compare, ecdh_generate_keys, ecdh_shared_secret

#: Binds the derived key to this specific purpose; a different context on the
#: same key pair yields a completely different key.
_CONTEXT = b"tiny-ecdh-example v1"


def main():
    alice_private, alice_public = ecdh_generate_keys()
    bob_private, bob_public = ecdh_generate_keys()
    alice_key = ecdh_shared_secret(alice_private, bob_public).derive_key(_CONTEXT)
    bob_key = ecdh_shared_secret(bob_private, alice_public).derive_key(_CONTEXT)
    print(
        "Equal Key"
        if constant_time_compare(alice_key, bob_key)
        else "Error: Key Not Equal"
    )


if __name__ == "__main__":
    main()
