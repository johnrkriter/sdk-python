import pytest
import incountry
import uuid
import json
import sure
import httpretty

POPAPI_URL = "https://popapi.com"
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


def mock_backend():
    httpretty.register_uri(
        httpretty.GET,
        incountry.Storage.PORTALBACKEND_URI + '/countries',
        body=json.dumps(
            {"countries": [{"id": "RU", "direct": True}, {"id": "AG", "direct": False}]}
        ),
    )


@pytest.fixture()
def client():
    def cli(encrypt=True):
        return incountry.Storage(
            encrypt=encrypt,
            debug=True,
            environment_id='test',
            api_key='test',
            endpoint=POPAPI_URL,
            secret_key=SECRET_KEY,
        )

    return cli


# @httpretty.activate
# @pytest.mark.parametrize('record', TEST_RECORDS)
# @pytest.mark.parametrize('encrypt', [True, False])
# @pytest.mark.happy_path
# def test_write(client, record, encrypt):
#     mock_backend()
#     httpretty.register_uri(httpretty.POST, POPAPI_URL + "/v2/storage/records/" + COUNTRY)

#     client(encrypt).write(**record)

#     received_payload = json.loads(httpretty.last_request().body)

#     assert received_payload['country'] == record['country']

#     if record.get('range_key', None):
#         assert received_payload['range_key'] == record['range_key']

#     for k in ['body', 'key', 'key2', 'key3', 'profile_key']:
#         if record.get(k, None) and encrypt:
#             assert received_payload[k] != record[k]
#         if record.get(k, None) and not encrypt:
#             assert received_payload[k] == record[k]


# @httpretty.activate
# @pytest.mark.parametrize('record', TEST_RECORDS)
# @pytest.mark.parametrize('encrypt', [True, False])
# @pytest.mark.happy_path
# def test_read(client, record, encrypt):
#     mock_backend()
#     stored_record = dict(record)
#     if encrypt:
#         stored_record = client(encrypt).encrypt_payload(stored_record)

#     httpretty.register_uri(
#         httpretty.GET,
#         POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/" + stored_record['key'],
#         body=json.dumps(stored_record),
#     )

#     record_response = client(encrypt).read(country=record['country'], key=record['key'])

#     assert record_response['country'] == record['country']
#     assert record_response['key'] == record['key']
#     if record.get('body'):
#         assert record_response['body'] == record['body']


# @httpretty.activate
# @pytest.mark.parametrize('record', [TEST_RECORDS[0]])
# @pytest.mark.parametrize('encrypt', [True, False])
# @pytest.mark.happy_path
# def test_read_not_found(client, record, encrypt):
#     mock_backend()
#     stored_record = dict(record)
#     if encrypt:
#         stored_record = client(encrypt).encrypt_payload(stored_record)

#     httpretty.register_uri(
#         httpretty.GET,
#         POPAPI_URL + "/v2/storage/records/" + COUNTRY + '/' + stored_record['key'],
#         status=404,
#     )

#     record_response = client(encrypt).read(country=record['country'], key=record['key'])

#     assert record_response is None


# @httpretty.activate
# @pytest.mark.parametrize('record', TEST_RECORDS)
# @pytest.mark.parametrize('encrypt', [True, False])
# @pytest.mark.happy_path
# def test_delete(client, record, encrypt):
#     mock_backend()
#     response = {'result': 'OK'}

#     stored_record = dict(record)
#     if encrypt:
#         stored_record = client(encrypt).encrypt_payload(stored_record)

#     httpretty.register_uri(
#         httpretty.DELETE,
#         POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/" + stored_record['key'],
#         body=json.dumps(response),
#     )

#     record_response = client(encrypt).delete(country=record['country'], key=record['key'])

#     record_response.should.be.equal(response)


@httpretty.activate
@pytest.mark.parametrize(
    'query,records',
    [
        ({"key": "key1"}, TEST_RECORDS),
        # ({"key2": "key2"}, TEST_RECORDS),
        # ({"key3": "key3"}, TEST_RECORDS),
        # ({"range_key": 1}, TEST_RECORDS),
        # ({"profile_key": "profile_key"}, TEST_RECORDS),
        # ({"key": ["key1-1", "key1-2"]}, TEST_RECORDS),
        # ({"key2": ["key2-1", "key2-2"]}, TEST_RECORDS),
        # ({"key3": ["key3-1", "key3-2"]}, TEST_RECORDS),
        # ({"range_key": [1, 2]}, TEST_RECORDS),
        # ({"range_key": {'$lte': 1}}, TEST_RECORDS),
        # ({"profile_key": ["profile_key1", "profile_key2"]}, TEST_RECORDS),
        # ({"limit": 1, "offset": 1}, TEST_RECORDS),
        # ({"key": "key1"}, []),
        # ({"limit": 1, "offset": 1}, []),
    ],
)
@pytest.mark.parametrize('encrypt', [True, False])
@pytest.mark.happy_path
def test_find(client, query, records, encrypt):
    mock_backend()
    enc_data = [dict(x) for x in records]
    if encrypt:
        for rec in enc_data:
            rec = client(encrypt).encrypt_payload(rec)

    httpretty.register_uri(
        httpretty.POST,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + '/find',
        body=json.dumps({'meta': {'total': len(enc_data)}, 'data': enc_data}),
    )

    find_response = client(encrypt).find(country=COUNTRY, **query)

    received_payload = json.loads(httpretty.last_request().body)
    received_payload.should.be.a(dict)
    received_payload.should.have.key('filter')
    received_payload.should.have.key('options')
    received_payload['options'].should.equal(
        {
            'limit': query.get('limit', incountry.Storage.FIND_LIMIT),
            'offset': query.get('offset', 0),
        }
    )

    if query.get('range_key', None):
        assert received_payload['filter']['range_key'] == query['range_key']

    for k in ['key', 'key2', 'key3', 'profile_key']:
        if query.get(k, None) and encrypt:
            assert received_payload['filter'][k] != query[k]
        if query.get(k, None) and not encrypt:
            assert received_payload['filter'][k] == query[k]

    find_response.should.be.a(dict)

    for data_record in find_response.get('data'):
        match = next(r for r in records if data_record['key'] == r['key'])
        for k in ['key', 'body']:
            if match.get(k, None):
                assert data_record[k] == match[k]
        for k in ['key2', 'key3', 'profile_key']:
            if match.get(k, None) and encrypt:
                assert data_record[k] != match[k]
            if match.get(k, None) and not encrypt:
                assert data_record[k] == match[k]


# @httpretty.activate
# @pytest.mark.parametrize(
#     'query,record',
#     [
#         ({"key": "key1"}, {"country": COUNTRY, "key": "key1"}),
#         ({"key": "key2"}, {"country": COUNTRY, "key": "key2", "body": "test"}),
#         ({"key": "key3"}, None),
#     ],
# )
# @pytest.mark.parametrize('encrypt', [True, False])
# @pytest.mark.happy_path
# def test_find_one(client, query, record, encrypt):
#     mock_backend()
#     stored_record = None
#     if record:
#         stored_record = dict(record)
#         if encrypt:
#             stored_record = client(encrypt).encrypt_payload(stored_record)

#     httpretty.register_uri(
#         httpretty.POST,
#         POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/find",
#         body=json.dumps(
#             {
#                 'meta': {'total': 0 if stored_record is None else 1},
#                 'data': [] if stored_record is None else [stored_record],
#             }
#         ),
#     )

#     find_one_response = client(encrypt).find_one(country=COUNTRY, **query)
#     find_one_response.should.equal(record)


# @httpretty.activate
# @pytest.mark.parametrize(
#     'query',
#     [
#         {"key": "key1", "limit": -1},
#         {"key": "key1", "limit": 101},
#         {"key": "key1", "limit": 1, "offset": -1},
#     ],
# )
# @pytest.mark.error_path
# def test_find_error(client, query):
#     httpretty.register_uri(
#         httpretty.POST,
#         POPAPI_URL + "/v2/storage/records/" + COUNTRY + '/find',
#         body=json.dumps({'meta': {'total': 0}, 'data': []}),
#     )

#     client().find.when.called_with(country=COUNTRY, **query).should.have.raised(
#         incountry.StorageClientError
#     )


# @pytest.mark.parametrize(
#     'kwargs',
#     [
#         ({}),
#         ({'api_key': 'test'}),
#         ({'environment_id': 'test'}),
#         ({'environment_id': 'test', 'api_key': 'test'}),
#         ({'environment_id': 'test', 'api_key': 'test', 'encrypt': True}),
#     ],
# )
# @pytest.mark.error_path
# def test_init_error_on_insufficient_args(client, kwargs):
#     incountry.Storage.when.called_with(**kwargs).should.have.raised(Exception)


# @httpretty.activate
# @pytest.mark.parametrize('record', [TEST_RECORDS[0]])
# @pytest.mark.parametrize('encrypt', [True, False])
# @pytest.mark.error_path
# def test_error_on_popapi_error(client, record, encrypt):
#     mock_backend()
#     stored_record = dict(record)
#     if encrypt:
#         stored_record = client(encrypt).encrypt_payload(stored_record)

#     httpretty.register_uri(
#         httpretty.POST, POPAPI_URL + "/v2/storage/records/" + COUNTRY + '/find', status=400
#     )
#     httpretty.register_uri(
#         httpretty.POST, POPAPI_URL + "/v2/storage/records/" + COUNTRY, status=400
#     )
#     httpretty.register_uri(
#         httpretty.GET,
#         POPAPI_URL + "/v2/storage/records/" + COUNTRY + '/' + stored_record['key'],
#         status=400,
#     )
#     httpretty.register_uri(
#         httpretty.DELETE,
#         POPAPI_URL + "/v2/storage/records/" + COUNTRY + '/' + stored_record['key'],
#         status=400,
#     )

#     client(encrypt).write.when.called_with(**record).should.have.raised(
#         incountry.StorageServerError
#     )
#     client(encrypt).read.when.called_with(**record).should.have.raised(incountry.StorageServerError)
#     client(encrypt).delete.when.called_with(**record).should.have.raised(
#         incountry.StorageServerError
#     )
#     client(encrypt).find.when.called_with(**record).should.have.raised(incountry.StorageServerError)
#     client(encrypt).find_one.when.called_with(**record).should.have.raised(
#         incountry.StorageServerError
#     )


# @pytest.mark.parametrize('record', [{}, {'country': COUNTRY}, {'key': 'key1'}])
# @pytest.mark.error_path
# def test_error_write_insufficient_args(client, record):
#     client().write.when.called_with(**record).should.have.raised(Exception)


# @pytest.mark.parametrize('record', [{'country': None, 'key': None}])
# @pytest.mark.error_path
# def test_error_read_insufficient_args(client, record):
#     client().read.when.called_with(**record).should.have.raised(Exception)


# @pytest.mark.parametrize('record', [{}, {'country': COUNTRY}, {'key': 'key1'}])
# @pytest.mark.error_path
# def test_error_delete_insufficient_args(client, record):
#     client().delete.when.called_with(**record).should.have.raised(Exception)


# @pytest.mark.parametrize('record', [{}])
# @pytest.mark.error_path
# def test_error_find_insufficient_args(client, record):
#     client().find.when.called_with(**record).should.have.raised(Exception)


# @pytest.mark.parametrize('record', [{}])
# @pytest.mark.error_path
# def test_error_find_one_insufficient_args(client, record):
#     client().find_one.when.called_with(**record).should.have.raised(Exception)
