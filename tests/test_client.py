import pytest
import incountry

ZONE_ID = "zone1"
API_KEY = "TestAPIKey123"

@pytest.fixture()
def client():
	c = incountry.Storage(zone_id=ZONE_ID, api_key=API_KEY)
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

