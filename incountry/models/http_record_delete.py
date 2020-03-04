from pydantic import BaseModel, constr


class HttpRecordDelete(BaseModel):
    body: constr(strict=True, regex="^$")
