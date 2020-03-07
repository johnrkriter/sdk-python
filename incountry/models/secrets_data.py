from pydantic import BaseModel, conlist, StrictBool, StrictInt, StrictStr


class Secret(BaseModel):
    secret: StrictStr
    version: StrictInt
    isKey: StrictBool = False


class SecretsData(BaseModel):
    currentVersion: StrictInt
    secrets: conlist(Secret, min_items=1)
