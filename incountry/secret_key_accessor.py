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

    def get_key(self, key_version=None):
        if key_version is not None and not isinstance(key_version, int):
            raise SecretKeyAccessorException(
                "Invalid secret key version requested. Version should be of type `int`"
            )

        keys_data = self._accessor_function()

        if isinstance(keys_data, str):
            return [keys_data, SecretKeyAccessor.DEFAULT_VERSION]

        try:
            validate(instance=keys_data, schema=secret_key_accessor_response_schema)
        except ValidationError as e:
            raise SecretKeyAccessorException("SecretKeyAccessor validation error") from e

        version_to_search = (
            key_version if key_version is not None else keys_data.get("currentKeyVersion")
        )

        for key_data in keys_data.get("keys"):
            if key_data.get("keyVersion") == version_to_search:
                return [key_data.get("key"), version_to_search]

        raise SecretKeyAccessorException(
            "Secret key not found for version {}".format(version_to_search)
        )
