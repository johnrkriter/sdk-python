from Crypto.Random import get_random_bytes
from incountry import InCrypto, InCryptoException
import pytest


def test_pack_unpack():
    ENC_DATA_LENGTH = 10
    data = get_random_bytes(ENC_DATA_LENGTH)
    salt = get_random_bytes(InCrypto.SALT_LENGTH)
    iv = get_random_bytes(InCrypto.IV_LENGTH)
    auth_tag = get_random_bytes(InCrypto.AUTH_TAG_LENGTH)

    parts = [salt, iv, data, auth_tag]
    packed = InCrypto.pack_hex(salt, iv, data, auth_tag)
    unpacked = InCrypto.unpack_hex(packed)

    assert all([a == b for a, b in zip(parts, unpacked)])


def test_unpack_error():
    with pytest.raises(InCryptoException) as exc_info:
        InCrypto.unpack_hex('')
    assert exc_info.type is InCryptoException


def test_enc_dec_simple():
    plaintext = ''
    password = 'password'

    cypher = InCrypto(password)

    enc = cypher.encrypt(plaintext)
    dec = cypher.decrypt(enc)

    assert plaintext == dec


def test_enc_dec_hieroglyphs():
    plaintext = '汉字'
    password = 'password'

    cypher = InCrypto(password)

    enc = cypher.encrypt(plaintext)
    dec = cypher.decrypt(enc)

    assert plaintext == dec


def test_dec_auth_error():
    with pytest.raises(InCryptoException) as exc_info:
        plaintext = '汉字'
        password = 'password'

        cypher = InCrypto(password)

        enc = cypher.encrypt(plaintext)
        cypher.decrypt(enc[2:])

    assert exc_info.type is InCryptoException


def test_no_password():
    with pytest.raises(TypeError) as exc_info:
        InCrypto()
    assert exc_info.type is TypeError

