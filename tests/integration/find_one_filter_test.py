import os
import pytest
import uuid
import sure
from pytest_testrail.plugin import pytestrail
from random import randint
from incountry import SecretKeyAccessor, Storage
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
DATA_SET = {
    "key": [uuid.uuid4().hex, uuid.uuid4().hex],
    "key2": [generate_sequence(randint(10, 100)), generate_sequence(randint(10, 100))],
    "key3": [generate_sequence(randint(10, 100)), generate_sequence(randint(10, 100))],
    "profile_key": [uuid.uuid4().hex, uuid.uuid4().hex],
    "range_key": [randint(0, 1000), randint(0, 1000)],
    "body": [generate_sequence(randint(10, 100)), generate_sequence(randint(10, 100))],
}
RANGE_KEYS_SET = [100, 123, 3236, 345, 98, 0]


@pytest.mark.parametrize("country", COUNTRIES)
@pytest.mark.parametrize("client", [COMMON_CLIENT, ENCRYPTED_CLIENT], ids=["common_client", "encrypted_client"])
@pytest.mark.parametrize("filter_key", ["key", "key2", "key3", "profile_key", "range_key"])
def test_find_one_by_array_of_keys(client, country, filter_key):
    keys_for_remove = []

    for value in DATA_SET[filter_key]:
        args = {filter_key: value}

        if filter_key != "key":
            args["key"] = uuid.uuid4().hex

        keys_for_remove.append(args["key"])
        client.write(country=country, **args)

    r = client.find_one(country=country, **{filter_key: DATA_SET[filter_key]})
    r.should.have.key("record")

    DATA_SET[filter_key].should.contain(r["record"][filter_key])

    index = randint(0, 1)
    r = client.find_one(country=country, **{filter_key: [DATA_SET[filter_key][index]]})
    r.should.have.key("record")
    r["record"][filter_key].should.equal(DATA_SET[filter_key][index])

    for key in keys_for_remove:
        client.delete(country=country, key=key)


@pytest.mark.parametrize("country", COUNTRIES)
@pytest.mark.parametrize("client", [COMMON_CLIENT, ENCRYPTED_CLIENT], ids=["common_client", "encrypted_client"])
def test_find_one_by_range_key_conditions(client, country):
    keys_for_remove = []

    for value in RANGE_KEYS_SET:
        key = uuid.uuid4().hex
        args = {"range_key": value, "key": key}

        keys_for_remove.append(key)

        client.write(country=country, **args)

    r = client.find_one(country=country, range_key={"$lt": RANGE_KEYS_SET[3]})
    r.should.have.key("record")

    (r["record"]["range_key"]).should.be.lower_than(RANGE_KEYS_SET[3])

    r = client.find_one(country=country, range_key={"$lte": RANGE_KEYS_SET[3]})
    r.should.have.key("record")

    (r["record"]["range_key"]).should.be.lower_than_or_equal_to(RANGE_KEYS_SET[3])

    r = client.find_one(country=country, range_key={"$gt": RANGE_KEYS_SET[3]})
    r.should.have.key("record")

    (r["record"]["range_key"]).should.be.greater_than(RANGE_KEYS_SET[3])

    r = client.find_one(country=country, range_key={"$gte": RANGE_KEYS_SET[3]})
    r.should.have.key("record")

    (r["record"]["range_key"]).should.be.greater_than_or_equal_to(RANGE_KEYS_SET[3])

    for key in keys_for_remove:
        client.delete(country=country, key=key)
