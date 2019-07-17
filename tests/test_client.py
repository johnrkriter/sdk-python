import pytest
import incountry
import uuid

@pytest.fixture()
def client():
	#zone_id=ZONE_ID, api_key=API_KEY, host=HOST)
	c = incountry.Storage(encrypt=False, use_ssl=False)
	yield c

def test_write_single_pop(client):
	key1 = str(uuid.uuid1())
	client.write(country='foo', key=key1)
	r = client.read(country='foo', key=key1)
	print(r)
	assert r is not None
	assert 'version' in r
	assert r['key'] == key1


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



