import pytest
import incountry

ZONE_ID = "zone1"
API_KEY = "TestAPIKey123"

PROD_ZONE_ID = '9daed72c-8d6d-4edc-acc2-0443e6f0dec1'
PROD_API_KEY = 'e979f6826ded42a388af4806822863df'

@pytest.fixture()
def client():
	c = incountry.Storage(zone_id=PROD_ZONE_ID, api_key=PROD_API_KEY)
	yield c

def test_write_single_pop(client):
	client.write(country='foo', key='key1')
	r = client.read(country='foo', key="key1")
	print(r)
	assert r is not None
	assert 'version' in r
	assert r['key'] == 'key1'


def test_read_single_pop(client):
	client.write(country='IT', key="record1", body="Welcome to Florence")
	client.write(country='IT', key="record2", body="Welcome to Rome")

	r = client.read(country='IT', key="record1")
	assert r['body'] == "Welcome to Florence"

	r = client.read(country='IT', key="record2")
	assert r['body'] == "Welcome to Rome"

def test_delete_single_pop(client):
	client.write(country='JP', key='record1', body='Konichiwa')
	r = client.read(country='JP', key='record1')
	assert r is not None

	client.delete(country='JP', key='record1')

	r = client.read(country='JP', key='record1')
	assert r is None



