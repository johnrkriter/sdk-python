from __future__ import absolute_import
import os
import socket
import json

import requests
from jsonschema import validate

from .incountry_crypto import InCrypto
from .validation import find_response_schema


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
        use_ssl=True,
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
        @param endpoint: Optional. Will use DNS routing by default.
        @param encrypt: Pass True (default) to encrypt values before storing
        @param secret_key: pass the encryption key for AES encrypting fields
        @param debug: pass True to enable some debug logging
        @param use_ssl: Pass False to talk to an unencrypted endpoint

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

        self.endpoint = endpoint or os.environ.get('INC_ENDPOINT')

        # Defaults to DNS routing if endpoint is None
        self.endpoint_map = {}

        self.use_ssl = use_ssl

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
            self.encrypt_record(data)

        r = requests.post(
            self.getendpoint(country, "/v2/storage/records/" + country),
            headers=self.headers(),
            data=json.dumps(data),
        )

        self.raise_if_server_error(r)

    def read(self, country, key):
        self.check_parameters(country, key)
        country = country.lower()

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
            self.decrypt_record(data)

        return data

    def find(
        self,
        country,
        key,
        profile_key=None,
        range_key=None,
        key2=None,
        key3=None,
        limit=0,
        offset=0,
    ):
        if country is None:
            raise StorageClientError("Missing country")

        if not isinstance(limit, int) or limit > 100:
            raise StorageClientError("limit should be an integer <= 100")

        if not isinstance(offset, int) or offset < 0:
            raise StorageClientError("limit should be an integer >= 0")

        filter_params = {}
        options = {"limit": limit, "offset": offset}

        if key:
            filter_params['key'] = key
        if profile_key:
            filter_params['profile_key'] = profile_key
        if range_key:
            filter_params['range_key'] = range_key
        if key2:
            filter_params['key2'] = key2
        if key3:
            filter_params['key3'] = key3

        r = requests.post(
            self.getendpoint(country, "/v2/storage/records/" + country),
            headers=self.headers(),
            data=json.dumps({"filter": filter_params, "options": options}),
        )

        self.raise_if_server_error(r)
        response = r.json()

        try:
            validate(instance=response, schema=find_response_schema)
        except Exception as e:
            raise StorageServerError('Invalid PoPAPI response', e)

        return {
            'meta': response['meta'],
            'data': [self.decrypt_record(record) for record in response['data']],
        }

    def find_one(self, offset=0, **kwargs):
        result = self.find(offset=offset, **kwargs)
        return result['data'][0] if len(result['data']) else None

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
    ########### Common functions
    ###########################################
    def log(self, *args):
        if self.debug:
            print("[incountry] ", args)

    def encrypt_record(self, record):
        if record.get('body'):
            record['body'] = self.crypto.encrypt(record['body'])
        return record

    def decrypt_record(self, record):
        if record.get('body'):
            record['body'] = self.crypto.decrypt(record['body'])
        return record

    def getendpoint(self, country, path):
        # TODO: Make countries set cover ALL countries, indicating mini or med POP
        protocol = "http"
        if self.use_ssl:
            protocol = "https"

        if not path.startswith("/"):
            path = "/" + path

        host = self.endpoint

        if not host:
            host = country + ".api.incountry.io"
            try:
                socket.gethostbyname(host)
            except socket.gaierror:
                print("Failed to lookup host for {}".format(host))
                # POP not registered yet, so fall back to US
                host = "us.api.incountry.io"

        res = "{}://{}{}".format(protocol, host, path)
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

