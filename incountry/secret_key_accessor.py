from pydantic import ValidationError

from .exceptions import StorageClientError
from .validation import validate_model
from .validation.utils import get_formatted_validation_error
from .models import SecretsData, SecretKeyAccessor as SecretKeyAccessorModel


class SecretKeyAccessor:
    DEFAULT_VERSION = 0

    @validate_model(SecretKeyAccessorModel)
    def __init__(self, accessor_function):
        self._accessor_function = accessor_function

    def get_secrets_data(self):
        try:
            secrets_data = self._accessor_function()
        except Exception as e:
            raise StorageClientError("Failed to retrieve secret keys data") from e

        if not isinstance(secrets_data, (str, dict)):
            raise StorageClientError(
                f"SecretKeyAccessor validation error: \n  "
                f"accessor_function - should return either str or secrets_data dict"
            )

        return secrets_data

    def get_secrets_raw(self, custom_encryption_enabled=False):
        secrets_data = self.get_secrets_data()

        if isinstance(secrets_data, str):
            return (secrets_data, SecretKeyAccessor.DEFAULT_VERSION, False)

        try:
            SecretsData.validate(secrets_data)
        except ValidationError as e:
            raise StorageClientError(
                f"SecretKeyAccessor validation error: {get_formatted_validation_error(e)}"
            ) from None

        return secrets_data

    def get_secret(self, version=None, is_for_custom_encryption=False):
        if version is not None and not isinstance(version, int):
            raise StorageClientError("Invalid secret version requested. Version should be of type `int`")

        secrets_data = self.get_secrets_raw()
        if isinstance(secrets_data, tuple):
            return secrets_data

        version_to_search = version if version is not None else secrets_data.get("currentVersion")

        for secret_data in secrets_data.get("secrets"):
            if secret_data.get("version") == version_to_search:
                is_key = secret_data.get("isKey", False)
                secret = secret_data.get("secret")
                if is_for_custom_encryption and not secret_data.get("isForCustomEncryption", False):
                    raise StorageClientError("Requested secret key for custom encryption. Got a regular key instead.")
                return (secret, version_to_search, is_key)

        raise StorageClientError("Secret not found for version {}".format(version_to_search))
