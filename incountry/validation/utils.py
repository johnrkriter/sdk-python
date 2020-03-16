from inspect import getfullargspec
from functools import reduce

from pydantic import ValidationError

from ..exceptions import StorageClientError


def function_args_to_kwargs(function, args, kwargs):
    func_args = getfullargspec(function)[0]
    if "self" in func_args:
        func_args = func_args[1:]
    kwargs.update(dict(zip(func_args, args)))


def format_loc(error_loc_data, extra_path=""):
    if len(error_loc_data) == 1:
        return error_loc_data[0]
    return error_loc_data[0] + "".join(
        map(lambda idx: "[{}]".format(idx if isinstance(idx, int) else f"'{idx}'"), list(error_loc_data)[1:])
    )


def get_formatter_validation_error(e, prefix="", path=""):
    return reduce(
        (lambda agg, error: f"{agg}\n  {prefix}{format_loc(error['loc'], path)} - {error['msg']}"), e.errors(), ""
    )


def validate_model_wrapper(function, model, **kwargs):
    try:
        return model.validate(kwargs).dict()
    except ValidationError as e:
        errors_report = get_formatter_validation_error(e)
        error_text = "Validation failed during {}():{}".format(function.__qualname__, errors_report)
        raise StorageClientError(error_text) from None
