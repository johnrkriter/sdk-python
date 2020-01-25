from jsonschema import validators, Draft7Validator
from jsonschema.exceptions import ValidationError

from .schemas import custom_encryption_configurations_schema

function_checker = Draft7Validator.TYPE_CHECKER.redefine_many({"function": lambda _, instance: callable(instance)})
inc_validator = validators.extend(Draft7Validator, type_checker=function_checker)


def validate(instance, schema):
    validator = inc_validator(schema)
    validator.validate(instance)


def validate_custom_encryption(configs):
    validate(configs, custom_encryption_configurations_schema)

    has_current_version = False
    for custom_encryption_config in configs:
        if custom_encryption_config.get("isCurrent", False) is True:
            if has_current_version:
                raise ValidationError("There must be at most one current version of custom encryption")
            else:
                has_current_version = True
