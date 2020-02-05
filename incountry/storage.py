from __future__ import absolute_import
import os

import json
from jsonschema.exceptions import ValidationError

from .incountry_crypto import InCrypto
from .validation.validator import validate_custom_encryption
from .secret_key_accessor import SecretKeyAccessor
from .exceptions import StorageClientError, InCryptoException

from .http_client import HttpClient


class Storage:
    FIND_LIMIT = 100

    def __init__(
        self,
        environment_id=None,
        client_id=None,
        client_secret=None,
        encrypt=True,
        secret_key_accessor=None,
        endpoint=None,
        auth_endpoint=None,
        debug=False,
    ):
        """
        Returns a client to talk to the InCountry storage network.

        To find the storage endpoint, we use this logic:

        - Attempt to connect to <country>.api.incountry.io
        - If that fails, then fall back to us.api.incountry.io which
            will forward data to miniPOPs

        @param environment_id: The id of the environment into which you wll store data
        @param client_id: Your client_id
        @param client_secret: Your client_secret
        @param endpoint: Optional. Will use DNS routing by default.
        @param auth_endpoint: Optional. Will use this endpoint to communicate with auth server.
        @param encrypt: Pass True (default) to encrypt values before storing
        @param secret_key_accessor: pass SecretKeyAccessor class instance which provides secret key for encrytion
        @param debug: pass True to enable some debug logging

        You can also set parameters via env vars:

        INC_ENVIRONMENT_ID
        INC_CLIENT_ID
        INC_CLIENT_SECRET
        INC_ENDPOINT
        """
        self.debug = debug

        self.env_id = environment_id or os.environ.get("INC_ENVIRONMENT_ID")
        if not self.env_id:
            raise ValueError("Please pass environment_id param or set INC_ENVIRONMENT_ID env var")

        client_id = client_id or os.environ.get("INC_CLIENT_ID")
        client_secret = client_secret or os.environ.get("INC_CLIENT_SECRET")
        if not isinstance(client_id, str) or len(client_id) == 0:
            raise ValueError("Please pass client_id param or set INC_CLIENT_ID env var")
        if not isinstance(client_secret, str) or len(client_secret) == 0:
            raise ValueError("Please pass client_secret param or set INC_CLIENT_SECRET env var")

        self.encrypt = encrypt
        if encrypt:
            if not isinstance(secret_key_accessor, SecretKeyAccessor):
                raise ValueError("Encryption is on. Provide secret_key_accessor parameter of class SecretKeyAccessor")
            self.crypto = InCrypto(secret_key_accessor)
        else:
            self.crypto = InCrypto()

        self.custom_encryption_configs = None

        self.http_client = HttpClient(
            env_id=self.env_id,
            client_id=client_id,
            client_secret=client_secret,
            endpoint=endpoint or os.environ.get("INC_ENDPOINT"),
            auth_endpoint=auth_endpoint,
            debug=self.debug,
        )

    def set_custom_encryption(self, configs):
        if not self.encrypt:
            raise StorageClientError("Cannot use custom encryption when encryption is off")
        try:
            validate_custom_encryption(configs)
        except ValidationError as e:
            raise StorageClientError("Invalid custom encryption format") from e
        version_to_use = next((c["version"] for c in configs if c.get("isCurrent", False) is True), None)
        self.crypto.set_custom_encryption(configs, version_to_use)

    def write(self, country: str, key: str, **record_kwargs):
        country = country.lower()
        data = {"country": country, "key": key}

        for k in ["body", "key2", "key3", "profile_key", "range_key"]:
            if record_kwargs.get(k):
                data[k] = record_kwargs.get(k)

        data_to_send = self.encrypt_record(data)
        self.http_client.write(country=country, data=data_to_send)
        return {"record": {"key": key, **record_kwargs}}

    def batch_write(self, country: str, records: list):
        # Storage.try_validate(records, batch_records_schema, StorageClientError, "Invalid records for batch_write")
        encrypted_records = [self.encrypt_record(record) for record in records]
        data_to_send = {"records": encrypted_records}
        self.http_client.batch_write(country=country, data=data_to_send)
        return {"records": records}

    def read(self, country: str, key: str):
        country = country.lower()
        key = self.hash_custom_key(key)
        response = self.http_client.read(country=country, key=key)
        return {"record": self.decrypt_record(response)}

    def find(self, country: str, limit: int = FIND_LIMIT, offset: int = 0, **filter_kwargs):
        if not isinstance(limit, int) or limit <= 0 or limit > self.FIND_LIMIT:
            raise StorageClientError("limit should be an integer > 0 and <= %s" % self.FIND_LIMIT)

        if not isinstance(offset, int) or offset < 0:
            raise StorageClientError("limit should be an integer >= 0")

        filter_params = self.prepare_filter_params(**filter_kwargs)
        options = {"limit": limit, "offset": offset}

        response = self.http_client.find(country=country, data={"filter": filter_params, "options": options})

        decoded_records = []
        undecoded_records = []
        for record in response["data"]:
            try:
                decoded_records.append(self.decrypt_record(record))
            except InCryptoException as error:
                undecoded_records.append({"rawData": record, "error": error})

        result = {
            "meta": response["meta"],
            "records": decoded_records,
        }
        if len(undecoded_records) > 0:
            result["errors"] = undecoded_records

        return result

    def find_one(self, offset=0, **kwargs):
        result = self.find(offset=offset, limit=1, **kwargs)
        return {"record": result["records"][0]} if len(result["records"]) else None

    def delete(self, country: str, key: str):
        country = country.lower()
        key = self.hash_custom_key(key)
        self.http_client.delete(country=country, key=key)
        return {"success": True}

    def migrate(self, country: str, limit: int = FIND_LIMIT):
        if not self.encrypt:
            raise StorageClientError("Migration not supported when encryption is off")

        current_secret_version = self.crypto.get_current_secret_version()

        find_res = self.find(country=country, limit=limit, version={"$not": current_secret_version})

        self.batch_write(country=country, records=find_res["records"])

        return {
            "migrated": find_res["meta"]["count"],
            "total_left": find_res["meta"]["total"] - find_res["meta"]["count"],
        }

    ###########################################
    # Common functions
    ###########################################
    def log(self, *args):
        if self.debug:
            print("[incountry] ", args)

    def is_json(self, data):
        try:
            json.loads(data)
        except ValueError:
            return False
        return True

    def hash_custom_key(self, value):
        return self.crypto.hash(value + ":" + self.env_id)

    def prepare_filter_params(self, **filter_kwargs):
        filter_params = {}
        for k in ["key", "key2", "key3", "profile_key"]:
            if filter_kwargs.get(k):
                if filter_kwargs.get(k, None) and isinstance(filter_kwargs[k], list):
                    filter_params[k] = [self.hash_custom_key(x) for x in filter_kwargs[k]]
                elif filter_kwargs.get(k, None):
                    filter_params[k] = self.hash_custom_key(filter_kwargs[k])
        if filter_kwargs.get("range_key", None):
            filter_params["range_key"] = filter_kwargs["range_key"]
        return filter_params

    def encrypt_record(self, record):
        res = dict(record)
        body = {"meta": {}, "payload": None}
        for k in ["key", "key2", "key3", "profile_key"]:
            if res.get(k):
                body["meta"][k] = res.get(k)
                res[k] = self.hash_custom_key(res[k])
        if res.get("body"):
            body["payload"] = res.get("body")

        [enc_data, key_version] = self.crypto.encrypt(json.dumps(body))
        res["body"] = enc_data
        res["version"] = key_version
        return res

    def decrypt_record(self, record):
        res = dict(record)
        if res.get("body"):
            res["body"] = self.crypto.decrypt(res["body"], res["version"])
            if self.is_json(res["body"]):
                body = json.loads(res["body"])
                if body.get("payload"):
                    res["body"] = body.get("payload")
                else:
                    del res["body"]
                for k in ["key", "key2", "key3", "profile_key"]:
                    if record.get(k) and body["meta"].get(k):
                        res[k] = body["meta"][k]
        return res
