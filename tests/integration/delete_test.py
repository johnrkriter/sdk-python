import os
import pytest
import uuid
import sure
from pytest_testrail.plugin import pytestrail
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


@pytestrail.case("C147")
@pytest.mark.parametrize("country", COUNTRIES)
@pytest.mark.parametrize("client", [COMMON_CLIENT, ENCRYPTED_CLIENT], ids=["common_client", "encrypted_client"])
def test_delete(client, country):
    key1 = uuid.uuid4().hex

    client.write(country=country, key=key1, body="Konichiwa")

    r = client.read(country=country, key=key1)
    assert r is not None

    client.delete(country=country, key=key1)

    client.read.when.called_with(country=country, key=key1).should.throw(StorageServerError)


@pytest.mark.parametrize("country", COUNTRIES)
@pytest.mark.parametrize("client", [COMMON_CLIENT, ENCRYPTED_CLIENT], ids=["common_client", "encrypted_client"])
def test_delete_non_existent_record(client, country):
    key1 = uuid.uuid4().hex
    client.delete.when.called_with(country=country, key=key1).should.throw(StorageServerError)
