from typing import Callable

from pydantic import BaseModel, validator, ValidationError

# from ..secret_key_accessor import SecretKeyAccessor

from .secrets_data import SecretsData
from ..validation.utils import get_formatted_validation_error


class SecretKeyAccessor(BaseModel):
    accessor_function: Callable

    @validator("accessor_function")
    def validate_secrets_data(cls, value):
        try:
            secrets_data = value()
        except Exception as e:
            raise ValueError("failed to retrieve secret keys data") from e

        if isinstance(secrets_data, str):
            return value

        if isinstance(secrets_data, dict):
            try:
                SecretsData.validate(secrets_data)
            except ValidationError as e:
                raise ValueError(
                    "should return proper secrets_data format. Got:"
                    + get_formatted_validation_error(e, "  ", "secrets_data")
                )
            return value

        raise ValueError("should return either str or secrets_data dict")
