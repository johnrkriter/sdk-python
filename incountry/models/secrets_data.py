from pydantic import BaseModel, conlist, conint, StrictBool, StrictStr, validator


class Secret(BaseModel):
    secret: StrictStr
    version: conint(strict=True, gt=0)
    isKey: StrictBool = False


class SecretsData(BaseModel):
    currentVersion: conint(strict=True, gt=0)
    secrets: conlist(Secret, min_items=1)

    @validator("secrets", each_item=True)
    def secrets_to_dict(cls, value):
        return value.dict()

    @validator("secrets")
    def validate_current_version_exists(cls, value, values):
        current_version_found = False
        for secret in value:
            if "currentVersion" in values and secret["version"] == values["currentVersion"]:
                current_version_found = True
        if not current_version_found:
            raise ValueError("non of the secret versions match currentVersion")
        return value
