InCountry Storage SDK
============

Usage
-----

1. Create storage instance
```
from incountry import Storage

storage = Storage(
    # Required to be passed in, or as environment variable INC_API_KEY
    api_key='string',

    # Required to be passed in, or as environment variable INC_ENVIRONMENT_ID
    environment_id='string'
)
```
2. Writes
```
write_response = storage.write(
    # Required country code of where to store the data
    country='string',

    # Required record key
    key='string',

    # Optional payload
    body='string',

    # Optional
    profile_key='string',

    # Optional
    range_key='string',

    # Optional
    key2='string',

    # Optional
    key3='string'
)
```
3. Reads
```
read_response = storage.read(
    # Required country code
    country='string',

    # Required record key
    key='string'
)
```
4. Deletes
```
delete_response = storage.delete(
    # Required country code
    country='string',

    # Required record key
    key='string'
)
```
Testing Locally
---------------

In terminal run `pytest` for unit and integration tests


Testrail Reports
---------------

pytest --testrail --tr-url=https://incountry.testrail.io/ --tr-email={username} --tr-password={password} --tr-testrun-project-id=5 {TR Project ID 5 = Python SDK}


Notes
-----
1. To use with pipenv, please run `pipenv install`
2. Tests should pass when using pipenv also. For this run `pipenv run pytest`
