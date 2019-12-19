import os
import pytest
import uuid
import json
import sure
from random import randrange
from incountry import SecretKeyAccessor, Storage

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


@pytest.mark.parametrize("country", COUNTRIES)
@pytest.mark.parametrize("client", [COMMON_CLIENT, ENCRYPTED_CLIENT], ids=["common_client", "encrypted_client"])
def test_write_and_read(client, country):
    key1 = uuid.uuid4().hex
    body = {"somekey": "somevalue"}

    client.write(country=country, key=key1, body=json.dumps(body))

    r = client.read(country=country, key=key1)

    r.should.have.key("record")
    r["record"].should.have.key("key")
    r["record"]["key"].should.equal(key1)
    r["record"]["body"].should.equal(json.dumps(body))

    client.delete(country=country, key=key1)


@pytest.mark.parametrize("country", COUNTRIES)
@pytest.mark.parametrize("client", [COMMON_CLIENT, ENCRYPTED_CLIENT], ids=["common_client", "encrypted_client"])
def test_write_and_read_optional_keys(client, country):
    key1 = uuid.uuid4().hex
    key2 = uuid.uuid4().hex
    key3 = uuid.uuid4().hex
    profile_key = uuid.uuid4().hex
    range_key = randrange(100)
    body = {
        "name": "PersonName",
    }

    client.write(
        country=country,
        key=key1,
        key2=key2,
        key3=key3,
        profile_key=profile_key,
        range_key=range_key,
        body=json.dumps(body)
    )

    r = client.read(country=country, key=key1)

    r.should.have.key("record")

    r["record"]["key"].should.equal(key1)
    r["record"]["key2"].should.equal(key2)
    r["record"]["key3"].should.equal(key3)
    r["record"]["profile_key"].should.equal(profile_key)
    r["record"]["range_key"].should.equal(range_key)
    r["record"]["body"].should.equal(json.dumps(body))

    client.delete(country=country, key=key1)


@pytest.mark.parametrize("country", COUNTRIES)
@pytest.mark.parametrize("client", [COMMON_CLIENT, ENCRYPTED_CLIENT], ids=["common_client", "encrypted_client"])
def test_write_and_read_with_empty_body(client, country):
    key1 = uuid.uuid4().hex
    body = None

    client.write(
        country=country,
        key=key1,
        body=json.dumps(body)
    )

    r = client.read(country=country, key=key1)
    r.should.have.key("record")

    r["record"]["key"].should.equal(key1)
    r["record"]["body"].should.equal(json.dumps(body))

    client.delete(country=country, key=key1)


@pytest.mark.parametrize("country", COUNTRIES)
@pytest.mark.parametrize("client", [COMMON_CLIENT, ENCRYPTED_CLIENT], ids=["common_client", "encrypted_client"])
def test_rewrite_data(client, country):
    key1 = uuid.uuid4().hex
    body = {
        "name": "PersonName",
    }

    client.write(
        country=country,
        key=key1,
        body=json.dumps(body)
    )

    r = client.read(country=country, key=key1)
    r.should.have.key("record")

    r["record"]["key"].should.equal(key1)
    r["record"]["body"].should.equal(json.dumps(body))

    body = {
        "name": "NewPersonName",
    }

    client.write(
        country=country,
        key=key1,
        body=json.dumps(body)
    )

    r = client.read(country=country, key=key1)
    r.should.have.key("record")

    r["record"]["key"].should.equal(key1)
    r["record"]["body"].should.equal(json.dumps(body))

    client.delete(country=country, key=key1)
