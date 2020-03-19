from pydantic import ValidationError
import wrapt


from .utils import function_args_to_kwargs, get_formatted_validation_error
from ..exceptions import StorageClientError, InCryptoException
from ..models import CustomEncryptionOptionsWithKey


def try_custom_encryption_with_key(custom_encryption_configs, key, key_version):
    configs_with_key = [{**config, "key": key, "keyVersion": key_version} for config in custom_encryption_configs]
    try:
        CustomEncryptionOptionsWithKey.validate({"configs": configs_with_key})
        return True
    except Exception as e:
        if isinstance(e, InCryptoException):
            return False
        else:
            raise e


@wrapt.decorator
def validate_custom_encryption_methods(function, storage_instance, args, kwargs):
    function_args_to_kwargs(function, args, kwargs)

    secrets_data = storage_instance.secret_key_accessor.get_secrets_raw()

    valid_key_found = False

    try:
        if isinstance(secrets_data, tuple):
            [key, key_version, *rest] = secrets_data
            validation_res = try_custom_encryption_with_key(kwargs["configs"], key, key_version)
            valid_key_found = valid_key_found or validation_res
        if isinstance(secrets_data, dict):
            for secret_data in secrets_data["secrets"]:
                validation_res = try_custom_encryption_with_key(
                    kwargs["configs"], secret_data["secret"].encode("utf8"), secret_data["version"]
                )
                valid_key_found = valid_key_found or validation_res
    except ValidationError as e:
        errors_report = get_formatted_validation_error(e)
        error_text = f"Validation failed during {function.__qualname__}():{errors_report}"
        raise StorageClientError(error_text) from None

    if not valid_key_found:
        raise StorageClientError(
            f"Validation failed during {function.__qualname__}(): "
            f"none of the available secrets are valid for custom encryption"
        )

    return function(**kwargs)
