from functools import reduce
from typing import List, Union, Dict

from pydantic import BaseModel, conint, StrictStr, StrictInt, validator


def flatten(l: list) -> list:
    return [item for sublist in l for item in sublist]


FIND_LIMIT = 100

STR_OPERATORS = ["$not"]
INT_OPERATOR_GROUPS = [STR_OPERATORS, ["$gt", "$gte"], ["$lt", "$lte"]]
INT_OPERATORS = flatten(INT_OPERATOR_GROUPS)


class FindFilter(BaseModel):
    limit: conint(ge=1, le=FIND_LIMIT, strict=True) = FIND_LIMIT
    offset: conint(ge=0, strict=True) = 0
    key: Union[StrictStr, List[StrictStr], Dict] = None
    key2: Union[StrictStr, List[StrictStr], Dict] = None
    key3: Union[StrictStr, List[StrictStr], Dict] = None
    profile_key: Union[StrictStr, List[StrictStr], Dict] = None
    range_key: Union[StrictInt, List[StrictInt], Dict] = None
    version: Union[StrictInt, List[StrictInt], Dict] = None

    @validator("*", pre=True)
    def check_dicts(cls, value, values, config, field):
        if field.name in ["limit", "offset"]:
            return value

        if isinstance(value, dict) and len(value) == 0:
            raise ValueError("Filter cannot be empty dict")

        if isinstance(value, dict) and field.type_.__args__[0] is StrictInt:
            for key in value:
                if key not in INT_OPERATORS:
                    raise ValueError(
                        "Incorrect dict filter. Must contain only the following keys: {}".format(INT_OPERATORS)
                    )
            for operator_group in INT_OPERATOR_GROUPS:
                total_operators_from_group = reduce(
                    lambda agg, operator: agg + 1 if operator in value else agg, operator_group, 0
                )
                if total_operators_from_group > 1:
                    raise ValueError(
                        "Incorrect dict filter. Must contain not more than one key from the following group: {}".format(
                            operator_group
                        )
                    )

        if isinstance(value, dict) and field.type_.__args__[0] is StrictStr:
            for key in value:
                if key not in STR_OPERATORS:
                    raise ValueError(
                        "Incorrect dict filter. Must contain only the following keys: {}".format(STR_OPERATORS)
                    )

        return value
