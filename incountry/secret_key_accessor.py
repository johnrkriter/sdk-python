from jsonschema import validate
from jsonschema.exceptions import ValidationError

from .exceptions import SecretKeyAccessorException

from .validation import secret_key_accessor_response_schema


class SecretKeyAccessor:
    DEFAULT_VERSION = 0

    def __init__(self, accessor_function):
        if not callable(accessor_function):
            raise SecretKeyAccessorException("Argument accessor_function must be a function")
        self._accessor_function = accessor_function

    def get_secret(self, version=None):
        if version is not None and not isinstance(version, int):
            raise SecretKeyAccessorException(
                "Invalid secret version requested. Version should be of type `int`"
            )

        secrets_data = self._accessor_function()

        if isinstance(secrets_data, str):
            return (secrets_data, SecretKeyAccessor.DEFAULT_VERSION)

        try:
            validate(instance=secrets_data, schema=secret_key_accessor_response_schema)
        except ValidationError as e:
            raise SecretKeyAccessorException("SecretKeyAccessor validation error") from e

        version_to_search = version if version is not None else secrets_data.get("currentVersion")

        for secret_data in secrets_data.get("secrets"):
            if secret_data.get("version") == version_to_search:
                return (secret_data.get("secret"), version_to_search)

        raise SecretKeyAccessorException(
            "Secret not found for version {}".format(version_to_search)
        )
