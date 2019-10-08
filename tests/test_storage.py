import pytest
import incountry
import uuid
import json
import sure
import httpretty

POPAPI_URL = "popapi.com"
COUNTRY = 'us'
SECRET_KEY = 'password'

TEST_RECORDS = [
    {"country": COUNTRY, "key": str(uuid.uuid1())},
    {"country": COUNTRY, "key": str(uuid.uuid1()), "body": "test"},
    {"country": COUNTRY, "key": str(uuid.uuid1()), "body": "test", "key2": "key2"},
    {"country": COUNTRY, "key": str(uuid.uuid1()), "body": "test", "key2": "key2", "key3": "key3"},
    {
        "country": COUNTRY,
        "key": str(uuid.uuid1()),
        "body": "test",
        "key2": "key2",
        "key3": "key3",
        "profile_key": "profile_key",
    },
    {
        "country": COUNTRY,
        "key": str(uuid.uuid1()),
        "body": "test",
        "key2": "key2",
        "key3": "key3",
        "profile_key": "profile_key",
        "range_key": 1,
    },
]


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
@pytest.mark.parametrize('record', TEST_RECORDS)
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

    assert received_payload['country'] == record['country']

    if record.get('range_key', None):
        assert received_payload['range_key'] == record['range_key']

    for k in ['body', 'key', 'key2', 'key3', 'profile_key']:
        if record.get(k, None):
            assert received_payload[k] != record[k]


@httpretty.activate
@pytest.mark.parametrize('record', TEST_RECORDS)
def test_read(client, record):
    stored_record = dict(record)
    stored_record = client.encrypt_record(stored_record)

    httpretty.register_uri(
        httpretty.GET,
        'https://' + POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/" + stored_record['key'],
        body=json.dumps(stored_record),
    )

    record_response = client.read(country=record['country'], key=record['key'])

    assert record_response['country'] == record['country']
    assert record_response['key'] == record['key']
    if record.get('body'):
        assert record_response['body'] == record['body']
    httpretty.reset()


@httpretty.activate
@pytest.mark.parametrize(
    'query,records',
    [
        ({"key": "key1", "limit": 1, "offset": 2}, TEST_RECORDS),
        ({"key2": "key2"}, TEST_RECORDS),
        ({"key3": "key3"}, TEST_RECORDS),
        ({"range_key": 1}, TEST_RECORDS),
        ({"profile_key": "profile_key"}, TEST_RECORDS),
        ({"key": "key2", "limit": 0, "offset": 1}, []),
    ],
)
def test_find(client, query, records):
    enc_data = [dict(x) for x in records]
    for rec in enc_data:
        rec = client.encrypt_record(rec)

    httpretty.register_uri(
        httpretty.POST,
        'https://' + POPAPI_URL + "/v2/storage/records/" + COUNTRY + '/find',
        body=json.dumps({'meta': {'total': len(enc_data)}, 'data': enc_data}),
    )

    find_response = client.find(country=COUNTRY, **query)

    received_payload = json.loads(httpretty.last_request().body)
    received_payload.should.be.a(dict)
    received_payload.should.have.key('filter')
    received_payload.should.have.key('options')
    received_payload['options'].should.equal(
        {'limit': query.get('limit', 0), 'offset': query.get('offset', 0)}
    )

    if query.get('range_key', None):
        assert received_payload['filter']['range_key'] == query['range_key']

    for k in ['key', 'key2', 'key3', 'profile_key']:
        if query.get(k, None):
            assert received_payload['filter'][k] != query[k]

    find_response.should.be.a(dict)

    for data_record in find_response.get('data'):
        match = next(r for r in records if data_record['key'] == r['key'])
        for k in ['key', 'body']:
            if match.get(k, None):
                assert data_record[k] == match[k]
        for k in ['key2', 'key3', 'profile_key']:
            if match.get(k, None):
                assert data_record[k] != match[k]


@httpretty.activate
@pytest.mark.parametrize(
    'query', [{"key": "key1", "limit": -1}, {"key": "key1", "limit": 1, "offset": -1}]
)
def test_find_error(client, query):
    httpretty.register_uri(
        httpretty.POST,
        'https://' + POPAPI_URL + "/v2/storage/records/" + COUNTRY + '/find',
        body=json.dumps({'meta': {'total': 0}, 'data': []}),
    )

    client.find.when.called_with(country=COUNTRY, **query).should.have.raised(Exception)


@httpretty.activate
@pytest.mark.parametrize(
    'query,record',
    [
        ({"key": "key1"}, {"country": COUNTRY, "key": "key1"}),
        ({"key": "key2"}, {"country": COUNTRY, "key": "key2", "body": "test"}),
        ({"key": "key3"}, None),
    ],
)
def test_find_one(client, query, record):
    stored_record = None
    if record:
        stored_record = dict(record)
        stored_record = client.encrypt_record(stored_record)

    httpretty.register_uri(
        httpretty.POST,
        'https://' + POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/find",
        body=json.dumps(
            {
                'meta': {'total': 0 if stored_record is None else 1},
                'data': [] if stored_record is None else [stored_record],
            }
        ),
    )

    find_one_response = client.find_one(country=COUNTRY, **query)
    find_one_response.should.equal(record)
