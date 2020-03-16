from typing import Callable

from pydantic import BaseModel, validator, ValidationError

# from ..secret_key_accessor import SecretKeyAccessor

from .secrets_data import SecretsData
from ..validation.utils import get_formatter_validation_error


class SecretKeyAccessor(BaseModel):
    accessor_function: Callable

    @validator("accessor_function")
    def validate_secrets_data(cls, value):
        secrets_data = value()

        if isinstance(secrets_data, str):
            return value

        if isinstance(secrets_data, dict):
            try:
                SecretsData.validate(secrets_data)
            except ValidationError as e:
                print()
                raise ValueError(
                    "should return proper secrets_data format\t"
                    + get_formatter_validation_error(e, "\t", "secrets_data")
                )
            return value

        raise ValueError("should return either str or secrets_data Dict")
