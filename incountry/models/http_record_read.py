from pydantic import BaseModel, conint

from .record import Record


class RecordFromServer(Record):
    version: conint(ge=0, strict=True)


class HttpRecordRead(BaseModel):
    body: RecordFromServer
