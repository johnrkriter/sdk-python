from pydantic import BaseModel, conlist, conint, StrictBool, StrictStr


class Secret(BaseModel):
    secret: StrictStr
    version: conint(strict=True, gt=0)
    isKey: StrictBool = False


class SecretsData(BaseModel):
    currentVersion: conint(strict=True, gt=0)
    secrets: conlist(Secret, min_items=1)
