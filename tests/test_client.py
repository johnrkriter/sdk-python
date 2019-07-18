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

def test_read_single_pop(client):
	client.write(country='mv', key="record1", body="Welcome to Japan")
	client.write(country='jp', key="record2", body="Welcome again to Japan")

	r = client.read(country='mv', key="record1")
	assert r['body'] == "Welcome to Japan"

	r = client.read(country='jp', key="record2")
	assert r['body'] == "Welcome again to Japan"

# def test_delete_single_pop(client):
# 	client.write(country='ruc1', key='record1', body='Konichiwa')
# 	r = client.read(country='ruc1', key='record1')
# 	assert r is not None

# 	client.delete(country='ruc1', key='record1')

# 	r = client.read(country='ruc1', key='record1')
# 	assert r is None

# def test_using_encryption():
# 	eclient = incountry.Storage(encrypt=True, use_ssl=True)
# 	eclient.write(country="ru", key="key1", body="You cant read this text")

# 	client = incountry.Storage(encrypt=False, use_ssl=True)
# 	# Keys won't clash because of encryption
# 	client.write(country="ru", key="key1", body="You CAN read this text")

# 	r = eclient.read(country="ru", key="key1")
# 	assert r['body'] == "You cant read this text"

# 	r = client.read(country="ru", key="key1")
# 	assert r['body'] == "You CAN read this text"


