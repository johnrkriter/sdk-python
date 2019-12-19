import os
import pytest
import uuid
import sure
from pytest_testrail.plugin import pytestrail
from random import randrange
from incountry import SecretKeyAccessor, Storage, StorageServerError

API_KEY = os.environ.get("INT_INC_API_KEY")
ENVIRONMENT_ID = os.environ.get("INT_INC_ENVIRONMENT_ID")
ENDPOINT = os.environ.get("INT_INC_ENDPOINT")
SECRETS_DATA = {
    "secrets": [{"secret": "supersecret", "version": 2}],
    "currentVersion": 2,
}
COUNTRIES = ("us",)
COMMON_CLIENT = Storage(
    encrypt=False,
    debug=True,
    api_key=API_KEY,
    environment_id=ENVIRONMENT_ID,
    endpoint=ENDPOINT,
)
ENCRYPTED_CLIENT = Storage(
    encrypt=True,
    debug=True,
    api_key=API_KEY,
    environment_id=ENVIRONMENT_ID,
    endpoint=ENDPOINT,
    secret_key_accessor=SecretKeyAccessor(lambda: SECRETS_DATA),
)


@pytest.fixture(autouse=True)
@pytest.mark.parametrize("country", COUNTRIES)
@pytest.mark.parametrize("client", [COMMON_CLIENT, ENCRYPTED_CLIENT], ids=["common_client", "encrypted_client"])
def expected_rows(client, country):
    # Code that will run before your test

    args = {
        "country": country,
        "key": uuid.uuid4().hex,
        "key2": uuid.uuid4().hex,
        "key3": uuid.uuid4().hex,
        "profile_key": uuid.uuid4().hex,
        "range_key": randrange(1000),
        "body": "some_body",
    }

    client.write(**args)

    yield args

    # Code that will run after your test, for example:

    client.delete(country=country, key=args["key"])


@pytest.mark.parametrize("country", COUNTRIES)
@pytest.mark.parametrize("client", [COMMON_CLIENT, ENCRYPTED_CLIENT], ids=["common_client", "encrypted_client"])
def test_find_one_by_country(client, country):
    r = client.find_one(country=country)
    r.should.have.key("record")


@pytest.mark.parametrize("country", COUNTRIES)
@pytest.mark.parametrize("client", [COMMON_CLIENT, ENCRYPTED_CLIENT], ids=["common_client", "encrypted_client"])
@pytest.mark.parametrize("key", ["key2", "key3", "profile_key", "range_key", "body"])
def test_find_one_by_different_keys(client, country, expected_rows, key):
    filter_keys = {key: expected_rows[key], "key": expected_rows["key"]}

    r = client.find_one(country=country, **filter_keys)
    r.should.have.key("record")

    r = r["record"]
    r.should.have.key(key)

    r[key].should.equal(expected_rows[key])


@pytest.mark.parametrize("country", COUNTRIES)
@pytest.mark.parametrize("client", [COMMON_CLIENT, ENCRYPTED_CLIENT], ids=["common_client", "encrypted_client"])
def test_find_one_empty_response(client, country):
    r = client.find_one(country=country, key=uuid.uuid4().hex)
    r.should.equal(None)


@pytest.mark.parametrize("country", COUNTRIES)
@pytest.mark.parametrize("client", [COMMON_CLIENT, ENCRYPTED_CLIENT], ids=["common_client", "encrypted_client"])
def test_find_one_by_not_int_range_key(client, country, expected_rows):
    client.find_one.when.called_with(country=country, range_key=str(expected_rows["range_key"]) + "str")\
        .should.throw(StorageServerError)
