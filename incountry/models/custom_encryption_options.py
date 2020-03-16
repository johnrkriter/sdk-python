from typing import Callable

from pydantic import BaseModel, conlist, validator, StrictStr, StrictBool


class CustomEncryptionConfig(BaseModel):
    encrypt: Callable
    decrypt: Callable
    version: StrictStr
    isCurrent: StrictBool = False


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
