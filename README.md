### Tiny ECDH in Python

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
# Assumes private key is filled with random data before calling, and generates public key
alicePrivKey, alicePubKey = ecdh_generate_keys(alicePrivKey, alicePubKey)
```
2. Bob generates a random ECC key pair: {bobPrivKey, bobPubKey = bobPrivKey * G}
```Python
# Assumes private key is filled with random data before calling, and generates public key
bobPrivKey, bobPubKey = ecdh_generate_keys(bobPrivKey, bobPubKey)
```
3. Alice and Bob exchange their public keys through the insecure channel (e.g. over Bluetooth)

4. Alice calculates sharedKey = bobPubKey * alicePrivKey
```Python
# own private key + Bob's public key will generate a shared secret key
aliceSharedKey = ecdh_shared_secret(alicePrivKey, bobPubKey)
```

5. Bob calculates sharedKey = alicePubKey * bobPrivKey
```Python
# own private key + Alice's public key will generate a shared secret key
bobSharedKey = ecdh_shared_secret(bobPrivKey, alicePubKey)
```

6. Now both Alice and Bob have the same sharedKey == bobPubKey * alicePrivKey == alicePubKey * bobPrivKey

```Python
assert aliceSharedKey == bobSharedKey
```

### TODO:

- Add more NIST curves
- Create a more pythonic alternative
