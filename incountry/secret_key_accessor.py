from pydantic import ValidationError

from .exceptions import InCryptoException
from .validation.utils import get_formatter_validation_error


class SecretKeyAccessor:
    DEFAULT_VERSION = 0

    def __init__(self, accessor_function):
        if not callable(accessor_function):
            raise InCryptoException("Argument accessor_function must be a function")
        self._accessor_function = accessor_function

    def validate_secrets_data(self, secrets_data):
        from .models import SecretsData

        if not isinstance(secrets_data, str):
            SecretsData.validate(secrets_data)

    def init(self):
        secrets_data = self._accessor_function()
        self.validate_secrets_data(secrets_data)

    def get_secret(self, version=None, ignore_length_validation=False):
        if version is not None and not isinstance(version, int):
            raise InCryptoException("Invalid secret version requested. Version should be of type `int`")

        secrets_data = self._accessor_function()
        if isinstance(secrets_data, str):
            return (secrets_data, SecretKeyAccessor.DEFAULT_VERSION, False)

        try:
            self.validate_secrets_data(secrets_data)
        except ValidationError as e:
            raise InCryptoException(
                f"SecretKeyAccessor validation error: {get_formatter_validation_error(e)}"
            ) from None

        from .incountry_crypto import InCrypto

        version_to_search = version if version is not None else secrets_data.get("currentVersion")

        for secret_data in secrets_data.get("secrets"):
            if secret_data.get("version") == version_to_search:
                is_key = secret_data.get("isKey", False)
                secret = secret_data.get("secret")
                if not ignore_length_validation and is_key and len(secret) != InCrypto.KEY_LENGTH:
                    raise InCryptoException("Key should be {}-characters long".format(InCrypto.KEY_LENGTH))
                return (secret, version_to_search, is_key)

        raise InCryptoException("Secret not found for version {}".format(version_to_search))
