from inspect import getfullargspec

import wrapt

from .utils import function_args_to_kwargs, validate_model_wrapper


def validate_model(model):
    @wrapt.decorator
    def decorator(function, instance, args, kwargs):
        function_args_to_kwargs(function, args, kwargs)

        validated_data = validate_model_wrapper(function, model, **kwargs)
        validated_data_dict = validated_data.__dict__

        func_args = getfullargspec(function)[0]
        for key in func_args:
            if key in validated_data_dict:
                kwargs[key] = validated_data_dict[key]
        return function(**kwargs)

    return decorator
