from inspect import getfullargspec
from typing import Callable

from pydantic import BaseModel, conlist, validator, StrictStr, StrictBool

CUSTOM_ENCRYPTION_METHODS_ARGS = ["input", "key", "key_version"]


class CustomEncryptionConfig(BaseModel):
    encrypt: Callable
    decrypt: Callable
    version: StrictStr
    isCurrent: StrictBool = False

    @validator("encrypt", "decrypt")
    def validate_methods_signature(cls, value):
        method_args = getfullargspec(value)[0]
        if method_args != CUSTOM_ENCRYPTION_METHODS_ARGS:
            raise ValueError(
                f"Invalid signature ({', '.join(method_args)}). Should be ({', '.join(CUSTOM_ENCRYPTION_METHODS_ARGS)})"
            )
        return value


class CustomEncryptionOptions(BaseModel):
    configs: conlist(CustomEncryptionConfig, min_items=1)

    @validator("configs")
    def check_versions(cls, value):
        has_current_version = False
        versions = []
        for custom_encryption_config in value:
            if custom_encryption_config["version"] in versions:
                raise ValueError("Versions must be unique")
            versions.append(custom_encryption_config["version"])
            if custom_encryption_config.get("isCurrent", False) is True:
                if has_current_version:
                    raise ValueError("There must be at most one current version of custom encryption")
                else:
                    has_current_version = True
        return value

    @validator("configs", each_item=True)
    def configs_to_dict(cls, value):
        return value.dict()
