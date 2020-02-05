from __future__ import absolute_import

import requests
import json
import time
from jsonschema.exceptions import ValidationError
from oauthlib.oauth2 import BackendApplicationClient
from requests_oauthlib import OAuth2Session

from .exceptions import StorageServerError
from .validation.validator import validate
from .validation.schemas import (
    find_response_schema,
    record_schema,
    write_response_schema,
)
from .__version__ import __version__


class HttpClient:
    PORTALBACKEND_URI = "https://portal-backend.incountry.com"
    DEFAULT_ENDPOINT = "https://us.api.incountry.io"
    DEFAULT_AUTH_ENDPOINT = "https://auth.incountry.io"

    def __init__(self, env_id, client_id, client_secret, endpoint=None, auth_endpoint=None, debug=False):
        self.client_id = client_id
        self.client_secret = client_secret
        self.endpoint = endpoint
        self.env_id = env_id
        self.debug = debug
        self.auth_endpoint = auth_endpoint or HttpClient.DEFAULT_AUTH_ENDPOINT

        self.log("Connecting to storage endpoint: ", self.endpoint)

        self.token = None
        self.refresh_access_token()

    def write(self, country, data):
        response = self.request(country, method="POST", data=json.dumps(data))
        HttpClient.validate_response(response, write_response_schema)
        return response

    def batch_write(self, country, data):
        response = self.request(country, path="/batchWrite", method="POST", data=json.dumps(data))
        HttpClient.validate_response(response, write_response_schema)
        return response

    def read(self, country, key):
        response = self.request(country, path="/" + key)
        HttpClient.validate_response(response, record_schema)
        return response

    def find(self, country, data):
        response = self.request(country, path="/find", method="POST", data=json.dumps(data))
        HttpClient.validate_response(response, find_response_schema)
        return response

    def delete(self, country, key):
        return self.request(country, path="/" + key, method="DELETE")

    def request(self, country, path="", method="GET", data=None):
        try:
            self.refresh_access_token()
            session = OAuth2Session(client_id=self.client_id, token=self.token,)

            endpoint = self.getendpoint(country, "/v2/storage/records/" + country + path)
            res = session.request(method=method, url=endpoint, headers=self.headers(), data=data)

            if res.status_code >= 400:
                raise StorageServerError("{} {} - {}".format(res.status_code, res.url, res.text))

            try:
                return res.json()
            except Exception:
                return res.text
        except Exception as e:
            raise StorageServerError(e) from e

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

        res = HttpClient.get_midpop_url(country) + path if is_midpop else "{}{}".format(self.DEFAULT_ENDPOINT, path)

        self.log("Endpoint: ", res)
        return res

    def get_headers(self):
        return {
            "x-env-id": self.env_id,
            "Content-Type": "application/json",
            "User-Agent": "SDK-Python/" + __version__,
        }

    def refresh_access_token(self):
        if self.token is None or self.token["expires_at"] <= time.time():
            client = BackendApplicationClient(client_id=self.client_id)
            auth = OAuth2Session(client=client)
            self.token = auth.fetch_token(
                token_url=self.auth_endpoint, client_id=self.client_id, client_secret=self.client_secret
            )

    def log(self, *args):
        if self.debug:
            print("[incountry] ", args)

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
        HttpClient.try_validate(instance, schema, StorageServerError, "Response validation failed")
