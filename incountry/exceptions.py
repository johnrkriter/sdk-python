class SecretKeyAccessorException(Exception):
    pass


class InCryptoException(Exception):
    pass


class StorageError(Exception):
    pass


class StorageClientError(StorageError):
    pass


class StorageServerError(StorageError):
    pass
