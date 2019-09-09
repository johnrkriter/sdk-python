# Introduction

This is the python SDK for the InCountry storage network. Sign up for a free account at
https://incountry.com, then copy your Environment ID (the UUID) and the API key.

Important notes
---------------
We've changed the encryption algorithm since version `0.2.0` so it is not compatible with earlier versions.


# Installation

Use `pip` or `pipenv` to install the package:

    pip3 install incountry

and now use the SDK:

    python

    > import incountry

    > incdb = incountry.Storage(env_id="4e00667a-58a4-420b-97b7-243073124b89", \
                  api_key="key.yowivz.8ec54a9e647d43cbbc66-8b3096e7a70f", secret_key="any secret value")

    > incdb.write(country='jp', key='key1', body="Store this data in Japan")

	> r = incdb.read(country='jp', key='key1')
	> print(r)
	{'body': 'Store this data in Japan', 'key': 'key1', 'key2': None, 'key3': None, 'profile_key': None, 'range_key': None, 'version': 1, 'zone_id': 645}

    > incdb.delete(country='jp', key='key1')
    > r = incdb.read(country='jp', key='key1')
    > print(r)
    None

Instead of passing parameters, you can configure the client in your environment:

    export INC_ZONE_ID=<zone id>
    export INC_API_KEY=<api key>
    export INC_SECRET_KEY=`uuidgen`


# API

## incountry.Storage(params)

Returns a storage API client.

    @param zone_id: The id of the zone into which you wll store data
    @param api_key: Your API key
    @param endpoint: Optional. Will use DNS routing by default.
    @param encrypt: Pass True (default) to encrypt values before storing
    @param secret_key: pass the encryption key for AES encrypting fields
    @param pass True to enable some debug logging
    @param use_ssl: Pass False to talk to an unencrypted endpoint

### Storage.write(params)

Writes a single record to the storage network.

    @param country: required - 2 letter country code indicating location to store data
    @param key: required - unique key for this record (unique within the zone and country)
    @param body: body of the record in any format
    @param profile_key: identifier of the end-customer which owns this data
    @param range_key: sorted key for the record, like a timestamp. BigInt type.
    @param key2: secondary key to lookup the record
    @param key3: secondary key to lookup the record

### Storage.read(params)

Reads a single record from the storage network.

    @param country: required - 2 letter country code indicating location where the data is stored
    @param key: required - primary key for this record

### Storage.delete(params)

Delete a single record from the storage network.

    @param country: required - 2 letter country code indicating location where the data is stored
    @param key: required - primary key for this record

