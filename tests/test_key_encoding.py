import pytest

from tiny_ecdh import (
    FIELD_BYTE_LENGTH,
    PRIVATE_KEY_BYTE_LENGTH,
    PUBLIC_KEY_BYTE_LENGTH,
    InvalidPrivateKeyError,
    InvalidPublicKeyError,
    PrivateKey,
    PublicKey,
    ecdh_generate_keys,
)

G_X = 0x00000003F0EBA16286A2D57EA0991168D4994637E8343E36
G_Y = 0x00000000D51FBC6C71A0094FA2CDD545B11C5C0C797324F1
G_HEX = (
    "04"
    "03f0eba16286a2d57ea0991168d4994637e8343e36"
    "00d51fbc6c71a0094fa2cdd545b11c5c0c797324f1"
)


def test_field_and_key_byte_lengths():
    assert FIELD_BYTE_LENGTH == 21
    assert PRIVATE_KEY_BYTE_LENGTH == 21
    assert PUBLIC_KEY_BYTE_LENGTH == 43


def test_private_key_round_trips_through_bytes_and_hex():
    private_key, _ = ecdh_generate_keys()
    assert PrivateKey.from_bytes(private_key.to_bytes()) == private_key
    assert PrivateKey.from_hex(private_key.to_hex()) == private_key
    assert len(private_key.to_bytes()) == PRIVATE_KEY_BYTE_LENGTH


def test_public_key_round_trips_through_bytes_and_hex():
    _, public_key = ecdh_generate_keys()
    assert PublicKey.from_bytes(public_key.to_bytes()) == public_key
    assert PublicKey.from_hex(public_key.to_hex()) == public_key
    assert len(public_key.to_bytes()) == PUBLIC_KEY_BYTE_LENGTH


def test_public_key_known_answer_vector_uses_uncompressed_form():
    public_key = PublicKey(G_X, G_Y)
    assert public_key.to_hex() == G_HEX
    assert PublicKey.from_hex(G_HEX) == public_key


def test_private_key_from_bytes_rejects_wrong_length():
    with pytest.raises(InvalidPrivateKeyError):
        PrivateKey.from_bytes(b"\x01" * (PRIVATE_KEY_BYTE_LENGTH - 1))
    with pytest.raises(InvalidPrivateKeyError):
        PrivateKey.from_bytes(b"\x01" * (PRIVATE_KEY_BYTE_LENGTH + 1))


def test_private_key_from_hex_rejects_malformed_hex():
    with pytest.raises(InvalidPrivateKeyError):
        PrivateKey.from_hex("not hex")


def test_private_key_from_bytes_rejects_out_of_range_scalar():
    with pytest.raises(InvalidPrivateKeyError):
        PrivateKey.from_bytes(b"\x00" * PRIVATE_KEY_BYTE_LENGTH)


def test_public_key_from_bytes_rejects_wrong_length():
    with pytest.raises(InvalidPublicKeyError):
        PublicKey.from_bytes(b"\x04" + b"\x00" * (PUBLIC_KEY_BYTE_LENGTH - 2))


def test_public_key_from_bytes_rejects_bad_prefix():
    good = PublicKey(G_X, G_Y).to_bytes()
    with pytest.raises(InvalidPublicKeyError):
        PublicKey.from_bytes(b"\x03" + good[1:])


def test_public_key_from_hex_rejects_malformed_hex():
    with pytest.raises(InvalidPublicKeyError):
        PublicKey.from_hex("zz")


def test_public_key_from_bytes_rejects_coordinate_outside_field():
    good = PublicKey(G_X, G_Y).to_bytes()
    oversized_x = (b"\xff" * FIELD_BYTE_LENGTH) + good[1 + FIELD_BYTE_LENGTH :]
    with pytest.raises(InvalidPublicKeyError):
        PublicKey.from_bytes(b"\x04" + oversized_x)
