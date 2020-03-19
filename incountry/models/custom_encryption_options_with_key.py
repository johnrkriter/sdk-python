from typing import Callable

from pydantic import BaseModel, conlist, validator, StrictBool, StrictInt, StrictStr

from ..exceptions import InCryptoException

CUSTOM_ENCRYPTION_METHODS_ARGS = ["input", "key", "key_version"]


class CustomEncryptionConfigWithKey(BaseModel):
    key: bytes
    keyVersion: StrictInt
    version: StrictStr
    isCurrent: StrictBool = False
    encrypt: Callable
    decrypt: Callable

    @validator("encrypt", pre=True)
    def validate_enc(cls, value, values):
        plaintext = "incountry"

        try:
            enc = value(input=plaintext, key=values["key"], key_version=values["keyVersion"])
        except Exception as e:
            raise InCryptoException(e) from None

        if not isinstance(enc, str):
            raise ValueError(f"should return str. Got {type(enc).__name__}")
        return value

    @validator("decrypt", pre=True)
    def validate_dec(cls, value, values):
        plaintext = "incountry"
        if "encrypt" not in values:
            return value

        try:
            enc = values["encrypt"](input=plaintext, key=values["key"], key_version=values["keyVersion"])
            dec = value(input=enc, key=values["key"], key_version=values["keyVersion"])
        except Exception as e:
            raise InCryptoException(e) from None

        if not isinstance(dec, str):
            raise ValueError(f"should return str. Got {type(dec).__name__}")
        if dec != plaintext:
            raise ValueError(f"decrypted data doesn't match the original input")

        return value


class CustomEncryptionOptionsWithKey(BaseModel):
    configs: conlist(CustomEncryptionConfigWithKey, min_items=1)
