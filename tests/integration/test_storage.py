import pytest
import incountry
import uuid
from pytest_testrail.plugin import pytestrail


@pytest.fixture()
def client():
    # env should contain: INC_ENV_ID and INC_API_KEY)
    yield incountry.Storage(encrypt=False, debug=True)

    
@pytestrail.case('С143')
def test_write_single_pop(client):
    key1 = str(uuid.uuid1())
    client.write(country='us', key=key1)
    r = client.read(country='us', key=key1)
    assert r is not None
    assert 'version' in r
    assert r['key'] == key1


@pytestrail.case('С144')
def test_read_single_pop(client):
    client.write(country='it', key="record1", body="Welcome to Florence")
    client.write(country='it', key="record2", body="Welcome to Rome")

    r = client.read(country='it', key="record1")
    assert r['body'] == "Welcome to Florence"

    r = client.read(country='it', key="record2")
    assert r['body'] == "Welcome to Rome"


@pytestrail.case('С147')    
def test_delete_single_pop(client):
    client.write(country='ru', key='record1', body='Konichiwa')
    r = client.read(country='ru', key='record1')
    assert r is not None

    client.delete(country='ru', key='record1')

    r = client.read(country='ru', key='record1')
    assert r is None

@pytestrail.case('С148')
def test_using_encryption():
    eclient = incountry.Storage(encrypt=True, secret_key="supersecret")
    eclient.write(country="us", key="key1", body="You cant read this text")

    client = incountry.Storage(encrypt=False)
    # Keys won't clash because of encryption
    client.write(country="us", key="key1", body="You CAN read this text")

    r = eclient.read(country="us", key="key1")
    assert r['body'] == "You cant read this text"

    r = client.read(country="us", key="key1")
    assert r['body'] == "You CAN read this text"

