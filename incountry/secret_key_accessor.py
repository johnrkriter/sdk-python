from .exceptions import SecretKeyAccessorException


class SecretKeyAccessor:
    def __init__(self, accessor_function):
        if not callable(accessor_function):
            raise SecretKeyAccessorException("Argument accessor_function must be a function")
        self._accessor_function = accessor_function

    def get_secret(self):
        return self._accessor_function()
