import pytest
import incountry
import uuid
import json
import sure

from incountry.incountry_crypto import InCrypto

import httpretty

POPAPI_URL = "popapi.com"
COUNTRY = 'us'
SECRET_KEY = 'password'

crypto = InCrypto(SECRET_KEY)


def omit_keys(d, keys):
    return {x: d[x] for x in d if x not in keys}


@pytest.fixture()
def client():
    yield incountry.Storage(
        encrypt=True,
        debug=True,
        environment_id='test',
        api_key='test',
        endpoint=POPAPI_URL,
        secret_key=SECRET_KEY,
    )


@httpretty.activate
@pytest.mark.parametrize(
    'record',
    [
        {"country": COUNTRY, "key": str(uuid.uuid1())},
        {"country": COUNTRY, "key": str(uuid.uuid1()), "body": "test"},
    ],
)
def test_write(client, record):
    httpretty.register_uri(
        httpretty.POST, 'https://' + POPAPI_URL + "/v2/storage/records/" + COUNTRY
    )

    client.write(
        country=record.get('country'),
        key=record.get('key'),
        body=record.get('body', None),
        profile_key=record.get('profile_key', None),
        range_key=record.get('range_key', None),
        key2=record.get('key2', None),
        key3=record.get('key3', None),
    )

    received_payload = json.loads(httpretty.last_request().body)
    omit_keys(received_payload, 'body').should.equal(omit_keys(record, 'body'))

    if record.get('body'):
        assert received_payload['body'] != record['body']


@httpretty.activate
@pytest.mark.parametrize(
    'record',
    [
        {"country": COUNTRY, "key": str(uuid.uuid1())},
        {"country": COUNTRY, "key": str(uuid.uuid1()), "body": "test"},
    ],
)
def test_read(client, record):
    stored_record = dict(record)
    if stored_record.get('body'):
        stored_record['body'] = crypto.encrypt(stored_record['body'])

    httpretty.register_uri(
        httpretty.GET,
        'https://' + POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/" + record.get('key'),
        body=json.dumps(stored_record),
    )

    record_response = client.read(country=record.get('country'), key=record.get('key'))

    record_response.should.equal(record)


@httpretty.activate
@pytest.mark.parametrize(
    'query,records',
    [
        (
            {"key": "key1"},
            [
                {"country": COUNTRY, "key": "key1"},
                {"country": COUNTRY, "key": "key1", "body": "test"},
            ],
        ),
        ({"key": "key2"}, []),
    ],
)
def test_find(client, query, records):
    enc_data = [dict(x) for x in records]
    for rec in enc_data:
        if rec.get('body'):
            rec['body'] = crypto.encrypt(rec['body'])

    httpretty.register_uri(
        httpretty.POST,
        'https://' + POPAPI_URL + "/v2/storage/records/" + COUNTRY,
        body=json.dumps({'meta': {'total': len(enc_data)}, 'data': enc_data}),
    )

    find_response = client.find(country=COUNTRY, **query)

    find_response.should.be.a(dict)
    find_response.get('data').should.equal(records)


@httpretty.activate
@pytest.mark.parametrize(
    'query,record_stored,record_original',
    [
        ({"key": "key1"}, {"country": COUNTRY, "key": "key1"}, {"country": COUNTRY, "key": "key1"}),
        (
            {"key": "key2"},
            {"country": COUNTRY, "key": "key2", "body": crypto.encrypt("test")},
            {"country": COUNTRY, "key": "key2", "body": "test"},
        ),
        ({"key": "key3"}, None, None),
    ],
)
def test_find_one(client, query, record_stored, record_original):
    httpretty.register_uri(
        httpretty.POST,
        'https://' + POPAPI_URL + "/v2/storage/records/" + COUNTRY,
        body=json.dumps(
            {
                'meta': {'total': 0 if record_stored is None else 1},
                'data': [] if record_stored is None else [record_stored],
            }
        ),
    )

    find_one_response = client.find_one(country=COUNTRY, **query)
    find_one_response.should.equal(record_original)


# body=None, profile_key=None, range_key=None, key2=None, key3=None
