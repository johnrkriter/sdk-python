from __future__ import absolute_import
import os
import socket
import json

import requests

from .incountry_crypto import InCrypto


class StorageError(Exception):
    pass


class StorageClientError(StorageError):
    pass


class StorageServerError(StorageError):
    pass


class Storage(object):
    FIND_LIMIT = 100

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

    def write(self, country: str, key: str, **record_kwargs):
        country = country.lower()
        data = {"country": country, "key": key}

        for k in ['body', 'key2', 'key3', 'profile_key', 'range_key']:
            if record_kwargs.get(k):
                data[k] = record_kwargs.get(k)

        if self.encrypt:
            self.encrypt_payload(data)

        r = requests.post(
            self.getendpoint(country, "/v2/storage/records/" + country),
            headers=self.headers(),
            data=json.dumps(data),
        )

        self.raise_if_server_error(r)

    def read(self, country: str, key: str):
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
            self.decrypt_payload(data)

        return data

    def find(self, country: str, limit: int = FIND_LIMIT, offset: int = 0, **filter_kwargs):
        if not isinstance(limit, int) or limit < 0 or limit > self.FIND_LIMIT:
            raise StorageClientError("limit should be an integer >= 0 and <= %s" % self.FIND_LIMIT)

        if not isinstance(offset, int) or offset < 0:
            raise StorageClientError("limit should be an integer >= 0")

        filter_params = {}
        options = {"limit": limit, "offset": offset}

        for k in ['key', 'key2', 'key3', 'profile_key', 'range_key']:
            if filter_kwargs.get(k):
                filter_params[k] = filter_kwargs.get(k)

        if self.encrypt:
            self.encrypt_payload(filter_params)

        r = requests.post(
            self.getendpoint(country, "/v2/storage/records/" + country + "/find"),
            headers=self.headers(),
            data=json.dumps({"filter": filter_params, "options": options}),
        )

        self.raise_if_server_error(r)
        response = r.json()

        return {
            'meta': response['meta'],
            'data': [self.decrypt_payload(record) for record in response['data']],
        }

    def find_one(self, offset=0, **kwargs):
        result = self.find(offset=offset, limit=1, **kwargs)
        return result['data'][0] if len(result['data']) else None

    def delete(self, country: str, key: str):
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

    def encrypt_payload(self, record):
        if record.get('body'):
            record['body'] = self.crypto.encrypt(record['body'])
        if record.get('key'):
            if isinstance(record.get('key'), list):
                record['key'] = [self.crypto.encrypt(x) for x in record['key']]
            else:
                record['key'] = self.crypto.encrypt(record['key'])
        for k in ['profile_key', 'key2', 'key3']:
            if record.get(k, None) and isinstance(record[k], list):
                record[k] = [self.crypto.hash(x + ':' + self.env_id) for x in record[k]]
            elif record.get(k, None):
                record[k] = self.crypto.hash(record[k] + ':' + self.env_id)
        return record

    def decrypt_payload(self, record):
        if record.get('body'):
            record['body'] = self.crypto.decrypt(record['body'])
        if record.get('key'):
            record['key'] = self.crypto.decrypt(record['key'])
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

    def raise_if_server_error(self, response):
        if response.status_code >= 400:
            raise StorageServerError(
                "{} {} - {}".format(response.status_code, response.url, response.text)
            )

