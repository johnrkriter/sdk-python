from __future__ import absolute_import
import os

import requests
import json

from .incountry_crypto import InCrypto


class StorageError(Exception):
    pass


class StorageClientError(StorageError):
    pass


class StorageServerError(StorageError):
    pass


class Storage(object):
    FIND_LIMIT = 100
    PORTALBACKEND_URI = "https://portal-backend.incountry.com"
    DEFAULT_ENDPOINT = "https://us.api.incountry.io"

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

        data_to_send = self.encrypt_record(data) if self.encrypt else data

        r = requests.post(
            self.getendpoint(country, "/v2/storage/records/" + country),
            headers=self.headers(),
            data=json.dumps(data_to_send),
        )

        self.raise_if_server_error(r)

    def read(self, country: str, key: str):
        country = country.lower()

        if self.encrypt:
            key = self.hash_custom_key(key)

        r = requests.get(
            self.getendpoint(country, "/v2/storage/records/" + country + "/" + key),
            headers=self.headers(),
        )
        if r.status_code == 404:
            # Not found is ok
            return None

        self.raise_if_server_error(r)
        data = r.json()

        return self.decrypt_record(data) if self.encrypt else data

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
            filter_params = self.hash_find_keys(filter_params)

        r = requests.post(
            self.getendpoint(country, "/v2/storage/records/" + country + "/find"),
            headers=self.headers(),
            data=json.dumps({"filter": filter_params, "options": options}),
        )

        self.raise_if_server_error(r)
        response = r.json()

        return {
            'meta': response['meta'],
            'data': [
                self.decrypt_record(record) if self.encrypt else record
                for record in response['data']
            ],
        }

    def find_one(self, offset=0, **kwargs):
        result = self.find(offset=offset, limit=1, **kwargs)
        return result['data'][0] if len(result['data']) else None

    def delete(self, country: str, key: str):
        country = country.lower()

        if self.encrypt:
            key = self.hash_custom_key(key)

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

    def hash_custom_key(self, value):
        return self.crypto.hash(value + ':' + self.env_id)

    def hash_find_keys(self, filter_params):
        res = dict(filter_params)
        for k in ['key', 'key2', 'key3', 'profile_key']:
            if res.get(k, None) and isinstance(res[k], list):
                res[k] = [self.hash_custom_key(x) for x in res[k]]
            elif res.get(k, None):
                res[k] = self.hash_custom_key(res[k])
        return res

    def encrypt_record(self, record):
        res = dict(record)
        body = {"meta": {}, "payload": None}
        for k in ['key', 'key2', 'key3', 'profile_key']:
            if res.get(k):
                body["meta"][k] = res.get(k)
                res[k] = self.hash_custom_key(res[k])
        if res.get('body'):
            body['payload'] = res.get('body')

        res['body'] = self.crypto.encrypt(json.dumps(body))
        return res

    def decrypt_record(self, record):
        res = dict(record)
        if res.get('body'):
            try:
                res['body'] = self.crypto.decrypt(res['body'])
                body = json.loads(res['body'])
                if body.get('payload'):
                    res['body'] = body.get('payload')
                else:
                    del res['body']
                for k in ['key', 'key2', 'key3', 'profile_key']:
                    if record.get(k) and body['meta'].get(k):
                        res[k] = body['meta'][k]
            except Exception:
                # Old data format
                res['body'] = self.crypto.decrypt(res['body'])
        return res

    def get_midpop_country_codes(self):
        r = requests.get(self.PORTALBACKEND_URI + '/countries')

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
            else "{}{}".format(self.DEFAULT_ENDPOINT, path)
        )

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

