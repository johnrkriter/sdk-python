from pydantic import BaseModel, conint, StrictStr, StrictInt


class Record(BaseModel):
    key: StrictStr
    body: StrictStr = None
    key2: StrictStr = None
    key3: StrictStr = None
    profile_key: StrictStr = None
    range_key: StrictInt = None
    version: conint(ge=0, strict=True) = None
