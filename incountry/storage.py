from __future__ import absolute_import
import os

import requests
import json

from .incountry_crypto import InCrypto

PORTALBACKEND_URI = "https://portal-backend.incountry.com"
DEFAULT_ENDPOINT = "https://us.api.incountry.io"


class StorageError(Exception):
    pass


class StorageClientError(StorageError):
    pass


class StorageServerError(StorageError):
    pass


class Storage(object):
    def __init__(
        self,
        environment_id=None,
        api_key=None,
        endpoint=None,
        encrypt=True,
        secret_key=None,
        debug=False,
    ):
        """
            Returns a client to talk to the InCountry storage network.

            To find the storage endpoint, we use this logic:

            - Attempt to connect to <country>.api.incountry.io
            - If that fails, then fall back to us.api.incountry.io which
              will forward data to miniPOPs

            @param environment_id: The id of the environment into which you wll store data
            @param api_key: Your API key
            @param encrypt: Pass True (default) to encrypt values before storing
            @param secret_key: pass the encryption key for AES encrypting fields
            @param debug: pass True to enable some debug logging

            You can set parameters via env vars also:

            INC_ENVIRONMENT_ID
            INC_API_KEY
            INC_ENDPOINT
            INC_SECRET_KEY
        """
        self.debug = debug

        self.env_id = environment_id or os.environ.get('INC_ENVIRONMENT_ID')
        if not self.env_id:
            raise ValueError("Please pass environment_id param or set INC_ENVIRONMENT_ID env var")

        self.api_key = api_key or os.environ.get('INC_API_KEY')
        if not self.api_key:
            raise ValueError("Please pass api_key param or set INC_API_KEY env var")

        self.endpoint = endpoint or os.environ.get(
            'INC_ENDPOINT'
        )  # or 'https://us.api.incountry.com'

        if self.endpoint:
            self.log("Connecting to storage endpoint: ", self.endpoint)
        self.log("Using API key: ", self.api_key)

        self.encrypt = encrypt
        if encrypt:
            self.secret_key = secret_key or os.environ.get('INC_SECRET_KEY')
            if not self.secret_key:
                raise ValueError(
                    "Encryption is on. Please pass secret_key param or set INC_SECRET_KEY env var"
                )
            self.crypto = InCrypto(self.secret_key)

    def write(
        self, country, key, body=None, profile_key=None, range_key=None, key2=None, key3=None
    ):

        self.check_parameters(country, key)
        country = country.lower()
        data = {"country": country, "key": key}
        if body:
            data['body'] = body
        if profile_key:
            data['profile_key'] = profile_key
        if range_key:
            data['range_key'] = range_key
        if key2:
            data['key2'] = key2
        if key3:
            data['key3'] = key3

        if self.encrypt:
            self.encrypt_data(data)

        r = requests.post(
            self.getendpoint(country, "/v2/storage/records/" + country),
            headers=self.headers(),
            data=json.dumps(data),
        )

        self.raise_if_server_error(r)

    def read(self, country, key):
        self.check_parameters(country, key)
        country = country.lower()

        if self.encrypt:
            key = self.crypto.encrypt(key)

        r = requests.get(
            self.getendpoint(country, "/v2/storage/records/" + country + "/" + key),
            headers=self.headers(),
        )
        if r.status_code == 404:
            # Not found is ok
            return None

        self.raise_if_server_error(r)
        data = r.json()

        if self.encrypt:
            self.decrypt_data(data)

        return data

    def delete(self, country, key):
        self.check_parameters(country, key)
        country = country.lower()

        if self.encrypt:
            key = self.crypto.encrypt(key)

        r = requests.delete(
            self.getendpoint(country, "/v2/storage/records/" + country + "/" + key),
            headers=self.headers(),
        )
        self.raise_if_server_error(r)
        return r.json()

    ###########################################
    # Common functions
    ###########################################
    def log(self, *args):
        if self.debug:
            print("[incountry] ", args)

    def encrypt_data(self, record):
        if self.secret_key is None:
            raise ValueError("Cannot encrypt data because secret_key is None")
        for k in ['key', 'body', 'profile_key', 'key2', 'key3']:
            if record.get(k, None):
                record[k] = self.crypto.encrypt(record[k])

    def decrypt_data(self, record):
        for k in ['key', 'body', 'profile_key', 'key2', 'key3']:
            if record.get(k, None):
                record[k] = self.crypto.decrypt(record[k])

    def get_midpop_country_codes(self):
        r = requests.get(PORTALBACKEND_URI + '/countries')
        self.raise_if_server_error(r)
        data = r.json()

        return [country['id'].lower() for country in data['countries'] if country['direct'] is True]

    def getendpoint(self, country, path):
        if not path.startswith("/"):
            path = "/" + path

        if self.endpoint:
            res = "{}{}".format(self.endpoint, path)
            self.log("Endpoint: ", res)
            return res

        midpops = self.get_midpop_country_codes()

        is_midpop = country in midpops

        res = (
            "https://{}.api.incountry.io{}".format(country, path)
            if is_midpop
            else "{}{}".format(DEFAULT_ENDPOINT, path)
        )

        self.log("Endpoint: ", res)
        return res

    def headers(self):
        return {
            'Authorization': "Bearer " + self.api_key,
            'x-env-id': self.env_id,
            'Content-Type': 'application/json',
        }

    def check_parameters(self, country, key):
        if country is None:
            raise StorageClientError("Missing country")
        if key is None:
            raise StorageClientError("Missing key")

    def raise_if_server_error(self, response):
        if response.status_code >= 400:
            raise StorageServerError(
                "{} {} - {}".format(response.status_code, response.url, response.text)
            )

