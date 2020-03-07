import uuid
import json

import pytest
import sure  # noqa: F401
import httpretty

from incountry import (
    StorageServerError,
    HttpClient,
    get_salted_hash,
)

POPAPI_URL = "https://popapi.com:8082"
COUNTRY = "us"


def get_key_hash(key):
    return get_salted_hash(key, "test")


@pytest.fixture()
def client():
    def cli(endpoint=POPAPI_URL):
        return HttpClient(env_id="test", api_key="test", endpoint=endpoint, debug=True)

    return cli


@httpretty.activate
@pytest.mark.parametrize(
    "response", [{}, [], True, "", {"key": "key"}],
)
@pytest.mark.error_path
def test_write_response_validation(client, response):
    httpretty.register_uri(
        httpretty.POST, POPAPI_URL + "/v2/storage/records/" + COUNTRY, body=json.dumps(response),
    )

    client().write.when.called_with(country=COUNTRY, data="data").should.have.raised(
        StorageServerError, "HTTP Response validation failed"
    )


@httpretty.activate
@pytest.mark.parametrize(
    "response", [{}, [], True, "", {"key": "key"}],
)
@pytest.mark.error_path
def test_batch_write_response_validation(client, response):
    httpretty.register_uri(
        httpretty.POST, POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/batchWrite", body=json.dumps(response),
    )

    client().batch_write.when.called_with(country=COUNTRY, data="data").should.have.raised(
        StorageServerError, "HTTP Response validation failed"
    )


@httpretty.activate
@pytest.mark.error_path
def test_read_response_validation(client):
    key = str(uuid.uuid1())
    key_hash = get_key_hash(key)

    httpretty.register_uri(
        httpretty.GET,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/" + key_hash,
        body=json.dumps({"key": key_hash}),
    )

    client().read.when.called_with(country=COUNTRY, key=key_hash).should.have.raised(
        StorageServerError, "HTTP Response validation failed"
    )


@httpretty.activate
@pytest.mark.parametrize(
    "query", [{"key": "key1"}],
)
@httpretty.activate
@pytest.mark.parametrize(
    "response",
    [
        {},
        {"meta": {"count": 1}, "data": []},
        {"meta": {"count": 1, "limit": 1}, "data": []},
        {"meta": {"count": 1, "limit": 1, "offset": 1}, "data": []},
        {"meta": {"count": 0, "limit": 0, "offset": 0, "total": 0}, "data": []},
        {"meta": {"count": 1, "limit": 1, "offset": 1, "total": 1}, "data": {}},
        {"meta": {"count": 1, "limit": 1, "offset": 1, "total": 1}, "data": ["not a record"]},
        {"meta": {"count": 1, "limit": 1, "offset": 1, "total": 1}, "data": [{"not_a_record_key": 0}]},
        {"meta": {"count": 1, "limit": 1, "offset": 1, "total": 1}, "data": [{"not_a_record_key": 0}]},
        {"data": [{"key": "key", "version": 1}]},
    ],
)
@pytest.mark.error_path
def test_find_response_validation(client, query, response):
    httpretty.register_uri(
        httpretty.POST, POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/find", body=json.dumps(response)
    )

    client().find.when.called_with(country=COUNTRY, data="data").should.have.raised(
        StorageServerError, "HTTP Response validation failed"
    )


@httpretty.activate
@pytest.mark.parametrize(
    "response", [True, {"key": "key"}],
)
@pytest.mark.error_path
def test_delete_response_validation(client, response):
    key = str(uuid.uuid1())
    key_hash = get_key_hash(key)

    httpretty.register_uri(
        httpretty.DELETE, POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/" + key_hash, body=json.dumps(response),
    )

    client().delete.when.called_with(country=COUNTRY, key=key_hash).should.have.raised(
        StorageServerError, "HTTP Response validation failed"
    )
