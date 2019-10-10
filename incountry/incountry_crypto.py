import hashlib
import hmac

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class InCryptoException(Exception):
    pass


class InCrypto:
    SALT_LENGTH = 64  # Bytes
    IV_LENGTH = 12  # Bytes
    AUTH_TAG_LENGTH = 16  # Bytes
    PBKDF2_ROUNDS = 10000
    DERIVED_KEY_LENGTH = 32  # Bytes
    PBKDF2_DIGEST = "sha512"

    @staticmethod
    def pack_hex(salt, iv, enc, auth_tag):
        parts = [salt, iv, enc, auth_tag]
        return "".join([x.hex() for x in parts])

    @staticmethod
    def unpack_hex(enc):
        b_data = bytes.fromhex(enc)
        min_len = InCrypto.SALT_LENGTH + InCrypto.IV_LENGTH + InCrypto.AUTH_TAG_LENGTH
        if len(b_data) < min_len:
            raise InCryptoException('Wrong cyphertext size')
        return [
            b_data[: InCrypto.SALT_LENGTH],
            b_data[InCrypto.SALT_LENGTH : InCrypto.SALT_LENGTH + InCrypto.IV_LENGTH],
            b_data[
                InCrypto.SALT_LENGTH + InCrypto.IV_LENGTH : len(b_data) - InCrypto.AUTH_TAG_LENGTH
            ],
            b_data[-InCrypto.AUTH_TAG_LENGTH :],
        ]

    def __init__(self, password):
        self.password = password

    def encrypt(self, raw):
        salt = get_random_bytes(InCrypto.SALT_LENGTH)
        iv = get_random_bytes(InCrypto.IV_LENGTH)
        key = self.get_key(self.password, salt)

        cipher = AES.new(key, AES.MODE_GCM, iv)
        try:
            [encrypted, auth_tag] = cipher.encrypt_and_digest(raw.encode("utf8"))
            return self.pack_hex(salt, iv, encrypted, auth_tag)
        except Exception as e:
            raise InCryptoException(e) from e

    def decrypt(self, packed_enc):
        [salt, iv, enc, auth_tag] = self.unpack_hex(packed_enc)
        key = self.get_key(self.password, salt)

        cipher = AES.new(key, AES.MODE_GCM, iv)

        try:
            return cipher.decrypt_and_verify(enc, auth_tag).decode("utf8")
        except Exception as e:
            raise InCryptoException(e) from e

    def get_key(self, password, salt):
        return hashlib.pbkdf2_hmac(
            InCrypto.PBKDF2_DIGEST,
            password.encode("utf8"),
            salt,
            InCrypto.PBKDF2_ROUNDS,
            InCrypto.DERIVED_KEY_LENGTH,
        )

    def hash(self, data):
        hash = (
            hmac.new(self.password.encode('utf-8'), data.encode('utf-8'), digestmod=hashlib.sha256)
            .digest()
            .hex()
        )
        return hash
