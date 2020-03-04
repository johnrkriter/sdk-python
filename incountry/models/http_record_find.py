from typing import List

from pydantic import BaseModel, conint, validator

from .record import Record


class MetaInfo(BaseModel):
    count: conint(ge=0, strict=True)
    limit: conint(ge=1, strict=True)
    offset: conint(ge=0, strict=True)
    total: conint(ge=0, strict=True)


class HttpRecordFind(BaseModel):
    data: List[Record]
    meta: MetaInfo

    @validator("data", each_item=True)
    def data_items__to_dict(cls, value):
        return value.__dict__

    @validator("meta")
    def meta_to_dict(cls, value):
        return value.__dict__
