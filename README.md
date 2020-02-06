InCountry Storage SDK
============

Installation
-----
The recommended way to install the SDK is to use `pipenv` (or `pip`):
```
$ pipenv install incountry
```

Usage
-----
To access your data in InCountry using Python SDK, you need to create an instance of `Storage` class.
```python
from incountry import Storage

storage = Storage(
    api_key="string",              # Required to be passed in, or as environment variable INC_API_KEY
    environment_id="string",       # Required to be passed in, or as environment variable INC_ENVIRONMENT_ID
    endpoint="string",             # Optional. Defines API URL. Can also be set up using environment variable INC_ENDPOINT
    encrypt=bool,                  # Optional. If False, encryption is not used
    debug=bool,                    # Optional. If True enables some debug logging
    secret_key_accessor=accessor,  # Instance of SecretKeyAccessor class. Used to fetch encryption secret
)
```
`api_key` and `environment_id` can be fetched from your dashboard on `Incountry` site.

`endpoint` defines API URL and is used to override default one.

You can turn off encryption (not recommended). Set `encrypt` property to `false` if you want to do this.

#### Encryption key/secret

`secret_key_accessor` is used to pass a key or secret used for encryption.

Note: even though SDK uses PBKDF2 to generate a cryptographically strong encryption key, you must make sure you provide a secret/password which follows modern security best practices and standards.

`SecretKeyAccessor` class constructor allows you to pass a function that should return either a string representing your secret or a dict (we call it `secrets_data` object):

```python
{
  "secrets": [{
       "secret": <str>,
       "version": <int>,   # Should be a positive integer
	   "isKey": <bool>  # Should be True only for user-defined encryption keys
    }
  }, ....],
  "currentVersion": <int>,
}
```

`secrets_data` allows you to specify multiple keys/secrets which SDK will use for decryption based on the version of the key or secret used for encryption. Meanwhile SDK will encrypt only using key/secret that matches `currentVersion` provided in `secrets_data` object.

This enables the flexibility required to support Key Rotation policies when secrets/keys need to be changed with time. SDK will encrypt data using current secret/key while maintaining the ability to decrypt records encrypted with old keys/secrets. SDK also provides a method for data migration which allows to re-encrypt data with the newest key/secret. For details please see `migrate` method.

SDK allows you to use custom encryption keys, instead of secrets. Please note that user-defined encryption key should be a 32-characters 'utf8' encoded string as required by AES-256 cryptographic algorithm.


Here are some examples how you can use `SecretKeyAccessor`.
```python
# Get secret from variable
from incountry import SecretKeyAccessor

password = "password"
secret_key_accessor = SecretKeyAccessor(lambda: password)

# Get secrets via http request
from incountry import SecretKeyAccessor
import requests as req

def get_secrets_data():
    url = "<your_secret_url>"
    r = req.get(url)
    return r.json() # assuming response is a `secrets_data` object

secret_key_accessor = SecretKeyAccessor(get_secrets_data)
```

### Writing data to Storage

Use `write` method in order to create/replace (by `key`) a record.
```python
record = storage.write(
    country="string",      # Required country code of where to store the data
    key="string",          # Required record key
    body="string",         # Optional payload
    profile_key="string",  # Optional
    range_key=integer,     # Optional
    key2="string",         # Optional
    key3="string",         # Optional
)

# `write` returns created record on success
```
#### Encryption
InCountry uses client-side encryption for your data. Note that only body is encrypted. Some of other fields are hashed.
Here is how data is transformed and stored in InCountry database:
```python
{
    key,          # hashed
    body,         # encrypted
    profile_key,  # hashed
    range_key,    # plain
    key2,         # hashed
    key3,         # hashed
}
```

#### Batches
Use `batch_write` method to create/replace multiple records at once

```
batch_success = storage.batch_write(
	country="string",     # Required country code of where to store the data
	records="list"        # Required list of records
)

# `batch_write` returns True on success
```


### Reading stored data

Stored record can be read by `key` using `readAsync` method. It accepts an object with two fields: `country` and `key`
```python
record = storage.read(
    country="string",      # Required country code
    key="string",          # Required record key
)
```

### Find records

It is possible to search by random keys using `find` method.
```python
records = storage.find(country, limit, offset, **filter_kwargs)
```
Parameters:
`country` - country code,
`limit` - maximum amount of records you'd like to retrieve. Defaults to 100,
`offset` - specifies the number of records to skip,
`filter_kwargs` - a filter parameters.

Here is the example of how `find` method can be used:
```python
records = storage.find(country="us", limit=10, offset=10, key2="kitty", key3=["mew", "purr"])
```
This call returns all records with `key2` equals `kitty` AND `key3` equals `mew` OR `purr`. The `options` parameter defines the number of records to return and the starting index. It can be used for pagination. Note: SDK returns 100 records at most.

The return object looks like the following:
```python
{
    "data": [...],
    "errors": [...],   # optional
    "meta": {
        "limit": 10,
        "offset": 10,
        "total": 124,  # total records matching filter, ignoring limit
    }
}
```
You can use the following types for filter parameters.
Single value:
```python
key2="kitty"
```
One of the values:
```python
key3=["mew", "purr"]
```
`range_key` is a numeric field so you can use range filter requests, for example:
```python
range_key={"$lt": 1000} # search for records with range_key < 1000
```
Available request options for `range_key`: `$lt`, `$lte`, `$gt`, `$gte`.

You can search by any keys: `key`, `key2`, `key3`, `profile_key`, `range_key`.

#### Error handling

There could be a situation when `find` method will receive records that could not be decrypted.
For example, if one changed the encryption key while the found data is encrypted with the older version of that key.
In such cases find() method return data will be as follows:

```python
{
    "data": [...],  # successfully decrypted records 
    "errors": [{
        "rawData",  # raw record which caused decryption error
        "error",    # decryption error description 
    }, ...],
    "meta": { ... }
}
```

### Find one record matching filter

If you need to find the first record matching filter, you can use the `find_one` method.
```python
record = storage.find_one(country, offset, **filter_kwargs)
```
If record is not found, it will return `None`.

### Delete records
Use `deleteAsync` method in order to delete a record from InCountry storage. It is only possible using `key` field.
```python
storage.delete(
    country="string",      # Required country code
    key="string",          # Required record key
)

# `delete` will raise an Exception if fails
```

## Data Migration and Key Rotation support
Using `secret_key_accessor` that provides `secrets_data` object enables key rotation and data migration support.

SDK introduces `migrate(country: str, limit: int)` method which allows you to re-encrypt data encrypted with old versions of the secret. You should specify `country` you want to conduct migration in and `limit` for precise amount of records to migrate. `migrate` return a dict which contains some information about the migration - the amount of records migrated (`migrated`) and the amount of records left to migrate (`total_left`) (which basically means the amount of records with version different from `currentVersion` provided by `secret_key_accessor`)

```
{
	"migrated": <int>
	"total_left": <int>
}
```

For a detailed example of a migration script please see `/examples/full_migration.py`

Custom Encryption Support
-----
SDK supports the ability to provide custom encryption/decryption methods if you decide to use your own algorithm instead of the default one.

`Storage.set_custom_encryption(configs)` allows you to pass an array of custom encryption configurations with the following schema, which enables custom encryption:

```python
{
    "encrypt": <callable>,
    "decrypt": <callable>,
    "isCurrent": <bool>,
    "version": <str>
}
```

Both `encrypt` and `decrypt` attributes should be functions implementing the following interface

```python
encrypt(raw:str, key:bytes, key_version:int) -> str:
    ...

decrypt(raw:str, key:bytes, key_version:int) -> str:
    ...
```
They should accept raw data to encrypt/decrypt, key data (represented as bytes array) and key version received from `SecretKeyAccessor`.
The resulted encrypted/decrypted data should be a string.

`version` attribute is used to differ one custom encryption from another and from the default encryption as well.
This way SDK will be able to successfully decrypt any old data if encryption changes with time.

`isCurrent` attribute allows to specify one of the custom encryption configurations to use for encryption. Only one configuration can be set as `"isCurrent": True`.

If none of the configurations have `"isCurrent": True` then the SDK will use default encryption to encrypt stored data. At the same time it will keep the ability to decrypt old data, encrypted with custom encryption (if any).

Here's an example of how you can set up SDK to use custom encryption (using Fernet encryption method from https://cryptography.io/en/latest/fernet/)

```python

def enc(text, key, key_ver):
        cipher = Fernet(key)
        return cipher.encrypt(text.encode("utf8")).decode("utf8")

def dec(ciphertext, key, key_ver):
    cipher = Fernet(key)
    return cipher.decrypt(ciphertext.encode("utf8")).decode("utf8")

custom_encryption_configs = [
    {
        "encrypt": enc,
        "decrypt": dec,
        "version": "test",
        "isCurrent": True,
    }
]

key = "<base64_key_data>" # Fernet uses 32-byte length key encoded using base64

secret_key_accessor = SecretKeyAccessor(
    lambda: {
        "currentVersion": 1,
        "secrets": [{"secret": key, "version": 1, "isKey": True}],
    }
)

storage = Storage(
    api_key="<api_key>",
    environment_id="<env_id>",
    secret_key_accessor=secret_key_accessor,
)

storage.set_custom_encryption(custom_encryption_configs)
storage.write(country="us", key="<key>", body="<body>")
```

Testing Locally
-----

1. In terminal run `pipenv run tests` for unit tests
2. In terminal run `pipenv run integrations` to run integration tests
