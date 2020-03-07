from functools import reduce

import wrapt
from pydantic import ValidationError

from .utils import format_loc
from ..exceptions import StorageServerError


def validate_http_response_wrapper(function, model, **kwargs):
    try:
        return model.validate(kwargs).dict()
    except ValidationError as e:
        errors_report = reduce(
            (lambda agg, error: "{}\n  {} - {}".format(agg, format_loc(error["loc"]), error["msg"])), e.errors(), ""
        )
        error_text = f"HTTP Response validation failed during {function.__qualname__}():{errors_report}"
        raise StorageServerError(error_text) from None


def validate_http_response(model):
    @wrapt.decorator
    def decorator(function, instance, args, kwargs):
        response = function(*args, **kwargs)
        validate_http_response_wrapper(function, model, **{"body": response})

        return response

    return decorator
