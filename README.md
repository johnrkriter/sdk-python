# Introduction

This is the python SDK for the InCountry storage network. Sign up for a free account at
https://incountry.com, then take note of your Zone ID and API key.

# Installation

Use `pip` or `pipenv` to install the package:

    pip3 install incountry

Setup your environment:

    export INC_ZONE_ID=<zone id>
    export INC_API_KEY=<api key>
   	export INC_SECRET_KEY=`uuidgen`

and now use the SDK:

    python

    > import incountry

    > incdb = incountry.Storage()
    > incdb.write(country='jp', key='key1', body="Store this data in Japan")

	> r = incdb.read(country='jp', key='key1')
	> print(r)
	{'body': 'Store this data in Japan', 'key': 'key1', 'key2': None, 'key3': None, 'profile_key': None, 'range_key': None, 'version': 1, 'zone_id': 645}

    > incdb.delete(country='jp', key='key1')
    > r = incdb.read(country='jp', key='key1')
    > print(r)
    None
