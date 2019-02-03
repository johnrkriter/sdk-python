from Crypto.Cipher import AES
import hmac
import hashlib
import os
import struct
from os import urandom


BLOCK_SIZE = 16  # Bytes
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
                chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

class LocoCrypto:
    def __init__(self, key):
        ba = hashlib.sha256(key.encode('utf-8')).hexdigest();
        self.salt = bytes.fromhex(ba)
        self.key = self.salt[0:16]
        self.iv = self.salt[16:32]

    def encrypt(self, raw):
        raw = pad(raw)
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return cipher.encrypt(raw).hex()

    def decrypt(self, enc):
        enc = bytes.fromhex(enc)
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return unpad(cipher.decrypt(enc)).decode('utf8')
        
    def hash(self, data):
        hash = hmac.new(self.salt, data.encode('utf-8'), digestmod=hashlib.sha256).digest().hex()
        return hash

if __name__ == '__main__':
    crypto = LocoCrypto('supersecret')
    original = 'I am the very model of a modern major general'
    print(original)
    enc = crypto.encrypt(original)
    print(enc)
    data = crypto.hash(original)
    print(data)