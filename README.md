InCountry Storage SDK
============

Important notes
---------------
We've changed the encryption algorithm since version `0.5.0` so it is not compatible with earlier versions.

Installation
-----
The recommended way to install the SDK is to use `pipenv` (or `pip`):
```
$ pipenv install incountry
```

Usage
-----
To access your data in InCountry using Python SDK, you need to create an instance of `Storage` class.
```
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

#### Encryption key

`secret_key_accessor` is used to pass secret/secrets used for encryption.

Note: even though SDK uses PBKDF2 to generate a cryptographically strong encryption key, you must make sure you provide a secret/password which follows modern security best practices and standards.

`SecretKeyAccessor` class constructor allows you to pass a function that should return either a string representing your secret or a dict (we call it `secrets_data` object):

```
{
  secrets: [{
       secret: <string>,
       version: <int>
  }, ....],
  currentVersion: <int>,
}
```

`secrets_data` allows you to specify multiple keys which SDK will use for decryption based on the version of the secret used for encryption. Meanwhile SDK will encrypt only using secret that matches `currentVersion` provided in `secrets_data` object.

This enables the flexibility required to support Key Rotation policies when secrets/keys need to be changed with time. SDK will encrypt data using newer secret while maintaining the ability to decrypt records encrypted with old secrets. SDK also provides a method for data migration which allows to re-encrypt data with the newest secret. For details please see `migrate` method.


Here are some examples how you can use `SecretKeyAccessor`.
```
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
```
record = storage.write(
	country="string",      # Required country code of where to store the data
	key="string",          # Required record key
	body="string",         # Optional payload
	profile_key="string",  # Optional
	range_key=integer,     # Optional
	key2="string",         # Optional
	key3="string"          # Optional
)

# `write` returns created record on success
```
#### Encryption
InCountry uses client-side encryption for your data. Note that only body is encrypted. Some of other fields are hashed.
Here is how data is transformed and stored in InCountry database:
```
{
	key,          # hashed
	body,         # encrypted
	profile_key,  # hashed
	range_key,    # plain
	key2,         # hashed
	key3          # hashed
 }
```

#### Batches
Use `batchWrite` method to create/replace multiple records at once

```
batch_success = storage.batchWrite(
	country="string",     # Required country code of where to store the data
	records="list"        # Required list of records
)

# `batchWrite` returns True on success
```


### Reading stored data

Stored record can be read by `key` using `readAsync` method. It accepts an object with two fields: `country` and `key`
```
record = storage.read(
	country="string",      # Required country code
	key="string"           # Required record key
)
```

### Find records

It is possible to search by random keys using `find` method.
```
records = storage.find(country, limit, offset, **filter_kwargs)
```
Parameters:
`country` - country code,
`limit` - maximum amount of records you'd like to retrieve. Defaults to 100,
`offset` - specifies the number of records to skip,
`filter_kwargs` - a filter parameters.

Here is the example of how `find` method can be used:
```
records = storage.find(country="us", limit=10, offset=10, key2="kitty", key3=["mew", "purr"])
```
This call returns all records with `key2` equals `kitty` AND `key3` equals `mew` OR `purr`. The `options` parameter defines the number of records to return and the starting index. It can be used for pagination. Note: SDK returns 100 records at most.

The return object looks like the following:
```
{
	"data": [/* kitties */],
	"meta": {
		"limit": 10,
		"offset": 10,
		"total": 124     # total records matching filter, ignoring limit
	}
}
```
You can use the following types for filter parameters.
Single value:
```
key2="kitty"
```
One of the values:
```
key3=["mew", "purr"]
```
`range_key` is a numeric field so you can use range filter requests, for example:
```
range_key={ "$lt": 1000 } # search for records with range_key < 1000
```
Available request options for `range_key`: `$lt`, `$lte`, `$gt`, `$gte`.

You can search by any keys: `key`, `key2`, `key3`, `profile_key`, `range_key`.

### Find one record matching filter

If you need to find the first record matching filter, you can use the `find_one` method.
```
record = storage.find_one(country, offset, **filter_kwargs)
```
If record is not found, it will return `None`.

### Delete records
Use `deleteAsync` method in order to delete a record from InCountry storage. It is only possible using `key` field.
```
storage.delete(
	country="string",      # Required country code
	key="string"           # Required record key
)

# delete will raise an Exception if fails
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

Testing Locally
-----

1. In terminal run `pipenv run tests` for unit tests
2. In terminal run `pipenv run integrations` to run integration tests
