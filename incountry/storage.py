from __future__ import absolute_import
import os
import json
from typing import List, Dict, Union

import requests

from jsonschema.exceptions import ValidationError

from .incountry_crypto import InCrypto
from .crypto_utils import decrypt_record, encrypt_record, get_salted_hash
from .validation.validator import validate, validate_custom_encryption
from .secret_key_accessor import SecretKeyAccessor
from .exceptions import StorageClientError, StorageServerError, InCryptoException
from .validation.schemas import (
    find_response_schema,
    record_schema,
    write_response_schema,
)
from .validation.validate_model import validate_model
from .models import Record, RecordListForBatch, Country, FindFilter
from .__version__ import __version__


class Storage(object):
    FIND_LIMIT = 100
    PORTALBACKEND_URI = "https://portal-backend.incountry.com"
    DEFAULT_ENDPOINT = "https://us.api.incountry.io"

    @staticmethod
    def get_midpop_url(country):
        return "https://{}.api.incountry.io".format(country)

    @staticmethod
    def try_validate(instance, schema, error_class, error_description):
        try:
            validate(instance=instance, schema=schema)
        except ValidationError as e:
            raise error_class(error_description) from e

    @staticmethod
    def validate_response(instance, schema):
        Storage.try_validate(instance, schema, StorageServerError, "Response validation failed")

    def __init__(
        self, environment_id=None, api_key=None, endpoint=None, encrypt=True, secret_key_accessor=None, debug=False,
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
        @param secret_key_accessor: pass SecretKeyAccessor class instance which provides secret key for encrytion
        @param debug: pass True to enable some debug logging

        You can set parameters via env vars also:

        INC_ENVIRONMENT_ID
        INC_API_KEY
        INC_ENDPOINT
        """
        self.debug = debug

        self.env_id = environment_id or os.environ.get("INC_ENVIRONMENT_ID")
        if not self.env_id:
            raise ValueError("Please pass environment_id param or set INC_ENVIRONMENT_ID env var")

        self.api_key = api_key or os.environ.get("INC_API_KEY")
        if not self.api_key:
            raise ValueError("Please pass api_key param or set INC_API_KEY env var")

        self.endpoint = endpoint or os.environ.get("INC_ENDPOINT")
        if self.endpoint:
            self.log("Connecting to storage endpoint: ", self.endpoint)

        self.log("Using API key: ", self.api_key)

        self.encrypt = encrypt
        if encrypt:
            if not isinstance(secret_key_accessor, SecretKeyAccessor):
                raise ValueError("Encryption is on. Provide secret_key_accessor parameter of class SecretKeyAccessor")
            self.crypto = InCrypto(secret_key_accessor)
        else:
            self.crypto = InCrypto()

        self.custom_encryption_configs = None

    def set_custom_encryption(self, configs):
        if not self.encrypt:
            raise StorageClientError("Cannot use custom encryption when encryption is off")
        try:
            validate_custom_encryption(configs)
        except ValidationError as e:
            raise StorageClientError("Invalid custom encryption format") from e
        version_to_use = next((c["version"] for c in configs if c.get("isCurrent", False) is True), None)
        self.crypto.set_custom_encryption(configs, version_to_use)

    @validate_model(Country)
    @validate_model(Record)
    def write(
        self,
        country: str,
        key: str,
        body: str = None,
        key2: str = None,
        key3: str = None,
        profile_key: str = None,
        range_key: int = None,
    ) -> Dict:
        record = {}
        for k in ["key", "body", "key2", "key3", "profile_key", "range_key"]:
            if locals().get(k, None):
                record[k] = locals().get(k, None)

        data_to_send = self.encrypt_record(record)
        response = self.request(country, method="POST", data=json.dumps(data_to_send))
        Storage.validate_response(response, write_response_schema)
        return {"record": record}

    @validate_model(Country)
    @validate_model(RecordListForBatch)
    def batch_write(self, country: str, records: list) -> Dict:
        encrypted_records = [self.encrypt_record(record) for record in records]
        data_to_send = {"records": encrypted_records}

        response = self.request(country, path="/batchWrite", method="POST", data=json.dumps(data_to_send))
        Storage.validate_response(response, write_response_schema)

        return {"records": records}

    @validate_model(Country)
    def update_one(self, country: str, filters: dict, **record_kwargs) -> Dict:
        existing_records_response = self.find(country=country, limit=1, offset=0, **filters)

        if existing_records_response["meta"]["total"] >= 2:
            raise StorageServerError("Multiple records found. Can not update")

        if existing_records_response["meta"]["total"] == 0:
            raise StorageServerError("Record not found")

        updated_record = {**existing_records_response["records"][0], **record_kwargs}

        self.write(country=country, **updated_record)

        return {"record": updated_record}

    @validate_model(Country)
    @validate_model(Record)
    def read(self, country: str, key: str) -> Dict:
        key = get_salted_hash(key, self.env_id)
        response = self.request(country, path="/" + key)
        Storage.validate_response(response, record_schema)
        return {"record": self.decrypt_record(response)}

    @validate_model(Country)
    @validate_model(FindFilter)
    def find(
        self,
        country: str,
        limit: int = None,
        offset: int = None,
        key: Union[str, List[str], Dict] = None,
        key2: Union[str, List[str], Dict] = None,
        key3: Union[str, List[str], Dict] = None,
        profile_key: Union[str, List[str], Dict] = None,
        range_key: Union[int, List[int], Dict] = None,
        version: Union[int, List[int], Dict] = None,
    ) -> Dict:
        filter_params = self.prepare_filter_params(
            key=key, key2=key2, key3=key3, profile_key=profile_key, range_key=range_key, version=version,
        )
        options = {"limit": limit, "offset": offset}

        response = self.request(
            country, path="/find", method="POST", data=json.dumps({"filter": filter_params, "options": options}),
        )
        Storage.validate_response(response, find_response_schema)

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

    @validate_model(Country)
    @validate_model(FindFilter)
    def find_one(
        self,
        country: str,
        offset: int = None,
        key: Union[str, List[str], Dict] = None,
        key2: Union[str, List[str], Dict] = None,
        key3: Union[str, List[str], Dict] = None,
        profile_key: Union[str, List[str], Dict] = None,
        range_key: Union[int, List[int], Dict] = None,
        version: Union[int, List[int], Dict] = None,
    ) -> Union[Dict, None]:
        result = self.find(
            country=country,
            limit=1,
            offset=offset,
            key=key,
            key2=key2,
            key3=key3,
            profile_key=profile_key,
            range_key=range_key,
            version=version,
        )
        return {"record": result["records"][0]} if len(result["records"]) else None

    @validate_model(Country)
    @validate_model(Record)
    def delete(self, country: str, key: str) -> Dict:
        key = get_salted_hash(key, self.env_id)
        self.request(country, path="/" + key, method="DELETE")
        return {"success": True}

    @validate_model(Country)
    @validate_model(FindFilter)
    def migrate(self, country: str, limit: int = None) -> Dict:
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

    def prepare_filter_params(self, **filter_kwargs):
        filter_params = {}
        for k in ["key", "key2", "key3", "profile_key"]:
            if filter_kwargs.get(k):
                if filter_kwargs.get(k, None) and isinstance(filter_kwargs[k], list):
                    filter_params[k] = [get_salted_hash(x, self.env_id) for x in filter_kwargs[k]]
                elif filter_kwargs.get(k, None):
                    filter_params[k] = get_salted_hash(filter_kwargs[k], self.env_id)
        if filter_kwargs.get("range_key", None):
            filter_params["range_key"] = filter_kwargs["range_key"]
        return filter_params

    def encrypt_record(self, record):
        return encrypt_record(self.crypto, record, self.env_id)

    def decrypt_record(self, record):
        return decrypt_record(self.crypto, record)

    def get_midpop_country_codes(self):
        r = requests.get(self.PORTALBACKEND_URI + "/countries")
        if r.status_code >= 400:
            raise StorageServerError("Unable to retrieve countries list")
        data = r.json()

        return [country["id"].lower() for country in data["countries"] if country["direct"]]

    def getendpoint(self, country, path):
        if not path.startswith("/"):
            path = "/" + path

        if self.endpoint:
            res = "{}{}".format(self.endpoint, path)
            self.log("Endpoint: ", res)
            return res

        midpops = self.get_midpop_country_codes()

        is_midpop = country in midpops

        res = Storage.get_midpop_url(country) + path if is_midpop else "{}{}".format(self.DEFAULT_ENDPOINT, path)

        self.log("Endpoint: ", res)
        return res

    def request(self, country, path="", method="GET", data=None):
        try:
            endpoint = self.getendpoint(country, "/v2/storage/records/" + country + path)
            res = requests.request(method=method, url=endpoint, headers=self.headers(), data=data)

            if res.status_code >= 400:
                raise StorageServerError("{} {} - {}".format(res.status_code, res.url, res.text))

            try:
                return res.json()
            except Exception:
                return res.text
        except Exception as e:
            raise StorageServerError(e) from e

    def headers(self):
        return {
            "Authorization": "Bearer " + self.api_key,
            "x-env-id": self.env_id,
            "Content-Type": "application/json",
            "User-Agent": "SDK-Python/" + __version__,
        }
