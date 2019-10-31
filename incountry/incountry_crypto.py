import hashlib
import os
import base64

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from .exceptions import InCryptoException


class InCrypto:
    SALT_LENGTH = 64  # Bytes
    IV_LENGTH = 12  # Bytes
    AUTH_TAG_LENGTH = 16  # Bytes
    PBKDF2_ROUNDS = 10000
    DERIVED_KEY_LENGTH = 32  # Bytes
    PBKDF2_DIGEST = "sha512"

    ENC_VERSION = "2"

    @staticmethod
    def pack_base64(salt, iv, enc, auth_tag):
        parts = [salt, iv, enc, auth_tag]
        joined_parts = b"".join(parts)
        return base64.b64encode(joined_parts).decode("utf8")

    @staticmethod
    def unpack_base64(enc):
        b_data = base64.b64decode(enc)
        min_len = InCrypto.SALT_LENGTH + InCrypto.IV_LENGTH + InCrypto.AUTH_TAG_LENGTH
        if len(b_data) < min_len:
            raise InCryptoException("Wrong ciphertext size")
        return [
            b_data[: InCrypto.SALT_LENGTH],
            b_data[InCrypto.SALT_LENGTH : InCrypto.SALT_LENGTH + InCrypto.IV_LENGTH],
            b_data[
                InCrypto.SALT_LENGTH + InCrypto.IV_LENGTH : len(b_data) - InCrypto.AUTH_TAG_LENGTH
            ],
            b_data[-InCrypto.AUTH_TAG_LENGTH :],
        ]

    def __init__(self, secret_key_accessor):
        self.secret_key_accessor = secret_key_accessor

    def __get_decryptor(self, version):
        if version == "0":
            return self.decrypt_v0
        if version == "1":
            return self.decrypt_v1
        if version == "2":
            return self.decrypt_v2

        raise InCryptoException("Unknown decryptor version requested")

    def encrypt(self, raw):
        salt = os.urandom(InCrypto.SALT_LENGTH)
        iv = os.urandom(InCrypto.IV_LENGTH)
        key = self.get_key(salt)

        encryptor = Cipher(
            algorithms.AES(key), modes.GCM(iv), backend=default_backend()
        ).encryptor()
        try:
            encrypted = encryptor.update(raw.encode("utf8")) + encryptor.finalize()
            auth_tag = encryptor.tag
            return self.ENC_VERSION + ":" + self.pack_base64(salt, iv, encrypted, auth_tag)
        except Exception as e:
            raise InCryptoException(e) from e

    def decrypt(self, enc):
        parts = enc.split(":")

        if len(parts) > 2:
            raise InCryptoException("Invalid ciphertext")

        version = "0"
        packed_enc = enc

        if len(parts) == 2:
            [version, packed_enc] = parts

        decryptor = self.__get_decryptor(version)

        try:
            return decryptor(packed_enc)
        except Exception as e:
            raise InCryptoException(e) from e

    def decrypt_v0(self, enc):
        secret = self.secret_key_accessor.get_secret()
        secret_bytes = hashlib.sha256(secret.encode("utf-8")).hexdigest()
        salt = bytes.fromhex(secret_bytes)
        key = salt[0:16]
        iv = salt[16:32]

        def unpad(data):
            return data[: -ord(data[len(data) - 1 :])]

        enc = bytes.fromhex(enc)
        decryptor = Cipher(
            algorithms.AES(key), modes.CBC(iv), backend=default_backend()
        ).decryptor()
        return unpad(decryptor.update(enc) + decryptor.finalize()).decode("utf8")

    def decrypt_v1(self, packed_enc):
        b_data = bytes.fromhex(packed_enc)
        min_len = InCrypto.SALT_LENGTH + InCrypto.IV_LENGTH + InCrypto.AUTH_TAG_LENGTH

        if len(b_data) < min_len:
            raise InCryptoException("Wrong ciphertext size")

        [salt, iv, enc, auth_tag] = [
            b_data[: InCrypto.SALT_LENGTH],
            b_data[InCrypto.SALT_LENGTH : InCrypto.SALT_LENGTH + InCrypto.IV_LENGTH],
            b_data[
                InCrypto.SALT_LENGTH + InCrypto.IV_LENGTH : len(b_data) - InCrypto.AUTH_TAG_LENGTH
            ],
            b_data[-InCrypto.AUTH_TAG_LENGTH :],
        ]

        key = self.get_key(salt)

        decryptor = Cipher(
            algorithms.AES(key), modes.GCM(iv, auth_tag), backend=default_backend()
        ).decryptor()
        return (decryptor.update(enc) + decryptor.finalize()).decode("utf8")

    def decrypt_v2(self, packed_enc):
        [salt, iv, enc, auth_tag] = self.unpack_base64(packed_enc)
        key = self.get_key(salt)

        decryptor = Cipher(
            algorithms.AES(key), modes.GCM(iv, auth_tag), backend=default_backend()
        ).decryptor()
        return (decryptor.update(enc) + decryptor.finalize()).decode("utf8")

    def get_key(self, salt):
        secret = self.secret_key_accessor.get_secret()
        return hashlib.pbkdf2_hmac(
            InCrypto.PBKDF2_DIGEST,
            secret.encode("utf8"),
            salt,
            InCrypto.PBKDF2_ROUNDS,
            InCrypto.DERIVED_KEY_LENGTH,
        )

    def hash(self, data):
        return hashlib.sha256(data.encode("utf-8")).hexdigest()
