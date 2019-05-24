# incountryapi
No description provided (generated by Swagger Codegen https://github.com/swagger-api/swagger-codegen)

This Python package is automatically generated by the [Swagger Codegen](https://github.com/swagger-api/swagger-codegen) project:

- API version: 2019-02-19T17:40:44Z
- Package version: 1.0.0
- Build package: io.swagger.codegen.languages.PythonClientCodegen

## Requirements.

Python 2.7 and 3.4+

## Installation & Usage
### pip install

If the python package is hosted on Github, you can install directly from Github

```sh
pip install git+https://github.com/GIT_USER_ID/GIT_REPO_ID.git
```
(you may need to run `pip` with root permission: `sudo pip install git+https://github.com/GIT_USER_ID/GIT_REPO_ID.git`)

Then import the package:
```python
import incountry
```

### Setuptools

Install via [Setuptools](http://pypi.python.org/pypi/setuptools).

```sh
python setup.py install
```

Then import the package:
```python
import incountry
```

## Getting Started

You will need an InCountry API Key and a unique seed for client-side encryption. Log in to https://portal.incountry.com to look up or reset your API key. The cryptography seed can be any unique value you choose, and will be used to encrypt your data prior to sending it to InCountry for storage. <b>Do not lose the cryptography seed</b> as InCountry <b>CANNOT</b> decrypt your data. Please follow the [installation procedure](#installation--usage) and then run the following:


```python
from incountry.InCountry import InCountry
from pprint import pprint

# Log in to https://portal.incountry.com to look up or reset your API key
APIKEY='YOUR_API_KEY'

# Choose a unique seed value for client-side encryption
CRYPTOSEED = 'supersecret'

# Specify which country your account data is stored in
ACCOUNT = 'DE'

# Specify which country your secured data will be processed in
COUNTRY = 'US'

db = InCountry(APIKEY, CRYPTOSEED, ACCOUNT)

db.write(country=COUNTRY, rowid="row0001", blob="blobbymcblobface", key1="foo", key2="bar")
db.write(country=COUNTRY, rowid="row0002", blob="I am the very model of a modern major general", key2="foo", key3="bar")
db.write(country=COUNTRY, rowid="row0003", blob="We hold these truths to be self-evident", key2="foo", key1="bar")
pprint(db.read(country=COUNTRY, rowid="row0001"))
pprint(db.lookup(country=COUNTRY, key2="foo"))
pprint(db.keylookup(country=COUNTRY, key1="foo"))
db.delete(country=COUNTRY, rowid="row0001")
db.delete(country=COUNTRY, rowid="row0002")
db.delete(country=COUNTRY, rowid="row0003")
 ```
## Documentation for API Endpoints

All URIs are relative to *https://87lh3zngr4.execute-api.us-east-1.amazonaws.com/prod*

Class | Method | HTTP request | Description
------------ | ------------- | ------------- | -------------
*DefaultApi* | [**delete_post**](docs/DefaultApi.md#delete_post) | **POST** /delete |
*DefaultApi* | [**keylookup_post**](docs/DefaultApi.md#keylookup_post) | **POST** /keylookup |
*DefaultApi* | [**lookup_post**](docs/DefaultApi.md#lookup_post) | **POST** /lookup |
*DefaultApi* | [**read_post**](docs/DefaultApi.md#read_post) | **POST** /read |
*DefaultApi* | [**write_post**](docs/DefaultApi.md#write_post) | **POST** /write |


## Documentation For Models

 - [Data](docs/Data.md)


## Documentation For Authorization


## api_key

- **Type**: API key
- **API key parameter name**: x-api-key
- **Location**: HTTP header


## Author
