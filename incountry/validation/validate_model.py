from pydantic import ValidationError
from functools import reduce, wraps
from inspect import getfullargspec

from ..exceptions import StorageClientError


def format_loc(error_loc_data):
    if len(error_loc_data) == 1:
        return error_loc_data[0]
    return error_loc_data[0] + "".join(
        map(lambda idx: "[{}]".format(idx if isinstance(idx, int) else "'{}'".format(idx)), list(error_loc_data)[1:])
    )


def validate_model_wrapper(function, model, *args, **kwargs):
    try:
        return model.validate(kwargs).dict()
    except ValidationError as e:
        errors_report = reduce(
            (lambda agg, error: "{}\n  {} - {}".format(agg, format_loc(error["loc"]), error["msg"])), e.errors(), ""
        )
        error_text = "Validation failed during {}():{}".format(function.__qualname__, errors_report)
        raise StorageClientError(error_text) from None


def validate_model(model):
    def decorator(function):
        @wraps(function)
        def wrapped_decorator(*args, **kwargs):
            validated_data_dict = validate_model_wrapper(function, model, *args, **kwargs)
            func_args = getfullargspec(function)[0]
            for key in func_args:
                if key in validated_data_dict:
                    kwargs[key] = validated_data_dict[key]
            return function(*args, **kwargs)

        return wrapped_decorator

    return decorator
