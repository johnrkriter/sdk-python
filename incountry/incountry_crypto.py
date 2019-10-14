import hmac
import hashlib

from Crypto.Cipher import AES

BLOCK_SIZE = 16  # Bytes
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[: -ord(s[len(s) - 1 :])]


class InCrypto:
    def __init__(self, key):
        ba = hashlib.sha256(key.encode('utf-8')).hexdigest()
        self.salt = bytes.fromhex(ba)
        self.key = self.salt[0:16]
        self.iv = self.salt[16:32]

    def encrypt(self, raw):
        raw = pad(raw)
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return cipher.encrypt(raw.encode('utf-8')).hex()

    def decrypt(self, enc):
        enc = bytes.fromhex(enc)
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return unpad(cipher.decrypt(enc)).decode('utf8')

    def hash(self, data):
        return hashlib.sha256(data.encode('utf-8')).hexdigest()
