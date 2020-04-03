from ..models import CustomEncryptionConfigMethodValidation


def try_custom_encryption_with_key(custom_encryption_config, key, key_version):
    config_with_key = {**custom_encryption_config, "key": key.encode("utf8"), "keyVersion": key_version}
    try:
        CustomEncryptionConfigMethodValidation.validate(config_with_key)
        return True
    except Exception as e:
        raise e


def validate_custom_encryption_config(config, secrets_data):
    valid_key_found = False

    if isinstance(secrets_data, tuple):
        [key, key_version, *rest] = secrets_data
        validation_res = try_custom_encryption_with_key(config, key, key_version)
        valid_key_found = valid_key_found or validation_res
    if isinstance(secrets_data, dict):
        for secret_data in secrets_data["secrets"]:
            validation_res = try_custom_encryption_with_key(config, secret_data["secret"], secret_data["version"])
            valid_key_found = valid_key_found or validation_res

    if not valid_key_found:
        raise ValueError(f"none of the available secrets are valid for custom encryption")

    return True
