class StorageException(Exception):
    pass


class StorageClientException(StorageException):
    pass


class StorageServerException(StorageException):
    pass


class InCryptoException(StorageException):
    pass
