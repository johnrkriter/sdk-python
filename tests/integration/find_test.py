import os
import pytest
import uuid
import sure
from pytest_testrail.plugin import pytestrail
from random import randrange, randint
from incountry import SecretKeyAccessor, Storage, StorageServerError
from tests.integration.helpers import generate_sequence

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
EXPECTED_ROWS_COUNT = 10


@pytest.fixture(autouse=True)
@pytest.mark.parametrize("country", COUNTRIES)
@pytest.mark.parametrize("client", [COMMON_CLIENT, ENCRYPTED_CLIENT], ids=["common_client", "encrypted_client"])
def expected_rows(client, country):
    # Code that will run before your test

    rows = []
    key2 = uuid.uuid4().hex
    key3 = uuid.uuid4().hex
    profile_key = uuid.uuid4().hex
    range_key = randrange(1000)
    body = generate_sequence(randint(10, 100))

    for k in range(0, EXPECTED_ROWS_COUNT):
        args = {
            "country": country,
            "key": uuid.uuid4().hex,
            "key2": key2,
            "key3": key3,
            "profile_key": profile_key,
            "range_key": range_key,
            "body": body,
        }

        client.write(**args)
        rows.append(args)

    yield rows

    # Code that will run after your test, for example:

    for row in rows:
        client.delete(country=country, key=row["key"])


@pytest.mark.parametrize("country", COUNTRIES)
@pytest.mark.parametrize("client", [COMMON_CLIENT, ENCRYPTED_CLIENT], ids=["common_client", "encrypted_client"])
@pytest.mark.parametrize("key", ["key2", "key3", "profile_key", "range_key", "body"])
def test_find_by_different_keys(client, country, expected_rows, key):
    print({key: expected_rows[0][key]})
    r = client.find(country=country, **{key: expected_rows[0][key]})
    print(r)

    r.should.have.key("data")
    r.should.have.key("meta")

    r["meta"]["total"].should.equal(EXPECTED_ROWS_COUNT)

    for k in range(0, EXPECTED_ROWS_COUNT):
        r["data"].should.have.key(key)
        r["data"][key].should.equal(expected_rows[0][key])


@pytest.mark.parametrize("country", COUNTRIES)
@pytest.mark.parametrize("client", [COMMON_CLIENT, ENCRYPTED_CLIENT], ids=["common_client", "encrypted_client"])
def test_find_empty_response(client, country):
    r = client.find(country=country, key=uuid.uuid4().hex)
    r.should.equal(None)

    r.should.have.key("data")
    r.should.have.key("meta")

    r["meta"]["total"].should.equal(0)


@pytest.mark.parametrize("country", COUNTRIES)
@pytest.mark.parametrize("client", [COMMON_CLIENT, ENCRYPTED_CLIENT], ids=["common_client", "encrypted_client"])
def test_find_by_not_int_range_key(client, country, expected_rows):
    client.find.when.called_with(country=country, range_key=str(expected_rows[0]["range_key"]) + "str") \
        .should.throw(StorageServerError)
