import pytest
import incountry
import uuid
import json
import sure
import httpretty

POPAPI_URL = "https://popapi.com"
COUNTRY = "us"
SECRET_KEY = "password"

TEST_RECORDS = [
    {"key": str(uuid.uuid1())},
    {"key": str(uuid.uuid1()), "body": "test"},
    {"key": str(uuid.uuid1()), "body": "test", "key2": "key2"},
    {"key": str(uuid.uuid1()), "body": "test", "key2": "key2", "key3": "key3"},
    {
        "key": str(uuid.uuid1()),
        "body": "test",
        "key2": "key2",
        "key3": "key3",
        "profile_key": "profile_key",
    },
    {
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
        incountry.Storage.PORTALBACKEND_URI + "/countries",
        body=json.dumps(
            {"countries": [{"id": "RU", "direct": True}, {"id": "AG", "direct": False}]}
        ),
    )


@pytest.fixture()
def client():
    def cli(encrypt=True, endpoint=POPAPI_URL):
        return incountry.Storage(
            encrypt=encrypt,
            debug=True,
            environment_id="test",
            api_key="test",
            endpoint=endpoint,
            secret_key=SECRET_KEY,
        )

    return cli


@httpretty.activate
@pytest.mark.parametrize("record", TEST_RECORDS)
@pytest.mark.parametrize("encrypt", [True, False])
@pytest.mark.happy_path
def test_write(client, record, encrypt):
    httpretty.register_uri(httpretty.POST, POPAPI_URL + "/v2/storage/records/" + COUNTRY)

    client(encrypt).write(country=COUNTRY, **record)

    received_record = json.loads(httpretty.last_request().body)

    if record.get("range_key", None):
        assert received_record["range_key"] == record["range_key"]

    for k in ["body", "key", "key2", "key3", "profile_key"]:
        if record.get(k, None) and encrypt:
            assert received_record[k] != record[k]
        if record.get(k, None) and not encrypt:
            assert received_record[k] == record[k]


@httpretty.activate
@pytest.mark.parametrize("record", TEST_RECORDS)
@pytest.mark.parametrize("encrypt", [True, False])
@pytest.mark.happy_path
def test_read(client, record, encrypt):
    stored_record = dict(record)
    if encrypt:
        stored_record = client(encrypt).encrypt_record(stored_record)

    httpretty.register_uri(
        httpretty.GET,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/" + stored_record["key"],
        body=json.dumps(stored_record),
    )

    record_response = client(encrypt).read(country=COUNTRY, key=record["key"])

    for k in ["body", "key", "key2", "key3", "profile_key", "range_key"]:
        if record.get(k, None):
            assert record_response[k] == record[k]


@httpretty.activate
@pytest.mark.parametrize("record", TEST_RECORDS)
@pytest.mark.parametrize("encrypt", [True, False])
@pytest.mark.happy_path
def test_read_old_data(client, record, encrypt):
    stored_record = dict(record)
    if encrypt:
        stored_record = client(encrypt).encrypt_record(stored_record)
        if record.get("body", None):
            stored_record["body"] = client(encrypt).crypto.encrypt(record["body"])
        else:
            del stored_record["body"]

    httpretty.register_uri(
        httpretty.GET,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/" + stored_record["key"],
        body=json.dumps(stored_record),
    )

    record_response = client(encrypt).read(country=COUNTRY, key=record["key"])

    for k in ["body", "range_key"]:
        if record.get(k, None):
            assert record_response[k] == record[k]

    for k in ["key", "key2", "key3", "profile_key"]:
        if record.get(k, None) and encrypt:
            assert record_response[k] != record[k]
        if record.get(k, None) and not encrypt:
            assert record_response[k] == record[k]


@httpretty.activate
@pytest.mark.parametrize("record", [TEST_RECORDS[0]])
@pytest.mark.parametrize("encrypt", [True, False])
@pytest.mark.happy_path
def test_read_not_found(client, record, encrypt):
    stored_record = dict(record)
    if encrypt:
        stored_record = client(encrypt).encrypt_record(stored_record)

    httpretty.register_uri(
        httpretty.GET,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/" + stored_record["key"],
        status=404,
    )

    record_response = client(encrypt).read(country=COUNTRY, key=record["key"])

    assert record_response is None


@httpretty.activate
@pytest.mark.parametrize("record", TEST_RECORDS)
@pytest.mark.parametrize("encrypt", [True, False])
@pytest.mark.happy_path
def test_delete(client, record, encrypt):
    response = {"result": "OK"}

    stored_record = dict(record)
    if encrypt:
        stored_record = client(encrypt).encrypt_record(stored_record)

    httpretty.register_uri(
        httpretty.DELETE,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/" + stored_record["key"],
        body=json.dumps(response),
    )

    record_response = client(encrypt).delete(country=COUNTRY, key=record["key"])

    record_response.should.be.equal(response)


@httpretty.activate
@pytest.mark.parametrize(
    "query,records",
    [
        ({"key": "key1"}, TEST_RECORDS),
        ({"key2": "key2"}, TEST_RECORDS),
        ({"key3": "key3"}, TEST_RECORDS),
        ({"range_key": 1}, TEST_RECORDS),
        ({"profile_key": "profile_key"}, TEST_RECORDS),
        ({"key": ["key1-1", "key1-2"]}, TEST_RECORDS),
        ({"key2": ["key2-1", "key2-2"]}, TEST_RECORDS),
        ({"key3": ["key3-1", "key3-2"]}, TEST_RECORDS),
        ({"range_key": [1, 2]}, TEST_RECORDS),
        ({"range_key": {"$lte": 1}}, TEST_RECORDS),
        ({"profile_key": ["profile_key1", "profile_key2"]}, TEST_RECORDS),
        ({"limit": 1, "offset": 1}, TEST_RECORDS),
        ({"key": "key1"}, []),
        ({"limit": 1, "offset": 1}, []),
    ],
)
@pytest.mark.parametrize("encrypt", [True, False])
@pytest.mark.happy_path
def test_find(client, query, records, encrypt):
    enc_data = [dict(x) for x in records]
    if encrypt:
        enc_data = [client(encrypt).encrypt_record(dict(x)) for x in records]

    httpretty.register_uri(
        httpretty.POST,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/find",
        body=json.dumps({"meta": {"total": len(enc_data)}, "data": enc_data}),
    )

    find_response = client(encrypt).find(country=COUNTRY, **query)

    received_record = json.loads(httpretty.last_request().body)
    received_record.should.be.a(dict)
    received_record.should.have.key("filter")
    received_record.should.have.key("options")
    received_record["options"].should.equal(
        {
            "limit": query.get("limit", incountry.Storage.FIND_LIMIT),
            "offset": query.get("offset", 0),
        }
    )

    if query.get("range_key", None):
        assert received_record["filter"]["range_key"] == query["range_key"]

    for k in ["key", "key2", "key3", "profile_key"]:
        if query.get(k, None) and encrypt:
            assert received_record["filter"][k] != query[k]
        if query.get(k, None) and not encrypt:
            assert received_record["filter"][k] == query[k]

    find_response.should.be.a(dict)

    for data_record in find_response.get("data"):
        match = next(r for r in records if data_record["key"] == r["key"])
        for k in ["body", "key", "key2", "key3", "profile_key"]:
            if match.get(k, None):
                assert data_record[k] == match[k]


@httpretty.activate
@pytest.mark.parametrize(
    "query,record",
    [
        ({"key": "key1"}, {"country": COUNTRY, "key": "key1"}),
        ({"key": "key2"}, {"country": COUNTRY, "key": "key2", "body": "test"}),
        ({"key": "key3"}, None),
    ],
)
@pytest.mark.parametrize("encrypt", [True, False])
@pytest.mark.happy_path
def test_find_one(client, query, record, encrypt):
    stored_record = None
    if record:
        stored_record = dict(record)
        if encrypt:
            stored_record = client(encrypt).encrypt_record(stored_record)

    httpretty.register_uri(
        httpretty.POST,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/find",
        body=json.dumps(
            {
                "meta": {"total": 0 if stored_record is None else 1},
                "data": [] if stored_record is None else [stored_record],
            }
        ),
    )

    find_one_response = client(encrypt).find_one(country=COUNTRY, **query)
    find_one_response.should.equal(record)


@httpretty.activate
@pytest.mark.parametrize("record", [TEST_RECORDS[-1]])
@pytest.mark.parametrize("update_key", ["key", "key2", "key3", "profile_key", "range_key"])
@pytest.mark.parametrize("encrypt", [True, False])
@pytest.mark.happy_path
def test_update(client, record, update_key, encrypt):
    stored_record = dict(record)
    if encrypt:
        stored_record = client(encrypt).encrypt_record(stored_record)

    httpretty.register_uri(httpretty.POST, POPAPI_URL + "/v2/storage/records/" + COUNTRY)
    httpretty.register_uri(
        httpretty.POST,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/find",
        body=json.dumps({"meta": {"total": 1}, "data": [stored_record]}),
    )

    data_for_update = dict(
        [
            (
                update_key,
                record[update_key] + 1
                if isinstance(record[update_key], int)
                else record[update_key] + "1",
            )
        ]
    )

    updated_record = client(encrypt).update_one(
        country=COUNTRY, filters=dict([(update_key, record[update_key])]), **data_for_update
    )
    received_record = json.loads(httpretty.last_request().body)

    for k in ["body", "key", "key2", "key3", "profile_key", "range_key"]:
        if k == update_key:
            assert updated_record[k] == data_for_update[k]
        else:
            assert updated_record[k] == record[k]

    if record.get("range_key", None) and update_key != "range_key":
        assert received_record["range_key"] == record["range_key"]

    if record.get("range_key", None) and update_key == "range_key":
        assert received_record["range_key"] == data_for_update["range_key"]

    for k in ["body", "key", "key2", "key3", "profile_key"]:
        if record.get(k, None) and encrypt:
            assert received_record[k] != record[k]

        if record.get(k, None) and not encrypt and update_key != k:
            assert received_record[k] == record[k]
        if record.get(k, None) and not encrypt and update_key == k:
            assert received_record[k] == data_for_update[k]


@httpretty.activate
@pytest.mark.parametrize(
    "record,country,countries",
    [
        ({"key": "key1"}, "ru", [{"id": "RU", "direct": True}, {"id": "AG", "direct": False}]),
        ({"key": "key1"}, "ag", [{"id": "RU", "direct": True}, {"id": "AG", "direct": False}]),
    ],
)
@pytest.mark.happy_path
def test_default_endpoint(client, record, country, countries):
    midpop_ids = [c["id"].lower() for c in countries if c["direct"]]
    is_midpop = country in midpop_ids
    endpoint = (
        incountry.Storage.get_midpop_url(country)
        if is_midpop
        else incountry.Storage.DEFAULT_ENDPOINT
    )

    countries_url = incountry.Storage.PORTALBACKEND_URI + "/countries"
    httpretty.register_uri(httpretty.GET, countries_url, body=json.dumps({"countries": countries}))

    read_url = endpoint + "/v2/storage/records/" + country + "/" + record["key"]
    httpretty.register_uri(httpretty.GET, read_url, body=json.dumps(record))

    record_response = client(encrypt=False, endpoint=None).read(country=country, key=record["key"])

    for k in ["body", "key", "key2", "key3", "profile_key", "range_key"]:
        if record.get(k, None):
            assert record_response[k] == record[k]

    latest_request = httpretty.HTTPretty.latest_requests[-1]
    prev_request = httpretty.HTTPretty.latest_requests[-2]

    latest_request_url = "https://" + latest_request.headers.get("Host", "") + latest_request.path
    prev_request_url = "https://" + prev_request.headers.get("Host", "") + prev_request.path

    assert latest_request_url == read_url
    assert prev_request_url == countries_url


@httpretty.activate
@pytest.mark.parametrize("record,country", [({"key": "key1"}, "ru"), ({"key": "key1"}, "ag")])
@pytest.mark.happy_path
def test_custom_endpoint(client, record, country):
    read_url = POPAPI_URL + "/v2/storage/records/" + country + "/" + record["key"]
    httpretty.register_uri(httpretty.GET, read_url, body=json.dumps(record))

    record_response = client(encrypt=False, endpoint=POPAPI_URL).read(
        country=country, key=record["key"]
    )

    for k in ["body", "key", "key2", "key3", "profile_key", "range_key"]:
        if record.get(k, None):
            assert record_response[k] == record[k]

    latest_request = httpretty.HTTPretty.last_request
    latest_request_url = "https://" + latest_request.headers.get("Host", "") + latest_request.path

    assert latest_request_url == read_url


@httpretty.activate
@pytest.mark.parametrize(
    "query",
    [
        {"key": "key1", "limit": -1},
        {"key": "key1", "limit": 101},
        {"key": "key1", "limit": 1, "offset": -1},
    ],
)
@pytest.mark.error_path
def test_find_error(client, query):
    httpretty.register_uri(
        httpretty.POST,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/find",
        body=json.dumps({"meta": {"total": 0}, "data": []}),
    )

    client().find.when.called_with(country=COUNTRY, **query).should.have.raised(
        incountry.StorageClientError
    )


@httpretty.activate
@pytest.mark.parametrize("records", [[TEST_RECORDS[0], TEST_RECORDS[1]], []])
@pytest.mark.parametrize("encrypt", [True, False])
@pytest.mark.error_path
def test_update_error(client, records, encrypt):
    enc_data = [dict(x) for x in records]
    if encrypt:
        enc_data = [client(encrypt).encrypt_record(dict(x)) for x in records]

    httpretty.register_uri(
        httpretty.POST,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/find",
        body=json.dumps({"meta": {"total": len(enc_data)}, "data": enc_data}),
    )

    client(encrypt).update_one.when.called_with(
        country=COUNTRY, filters={"key": "key1"}, **{"key2": "key2"}
    ).should.have.raised(incountry.StorageServerError)


@pytest.mark.parametrize(
    "kwargs",
    [
        ({}),
        ({"api_key": "test"}),
        ({"environment_id": "test"}),
        ({"environment_id": "test", "api_key": "test"}),
        ({"environment_id": "test", "api_key": "test", "encrypt": True}),
    ],
)
@pytest.mark.error_path
def test_init_error_on_insufficient_args(client, kwargs):
    incountry.Storage.when.called_with(**kwargs).should.have.raised(Exception)


@httpretty.activate
@pytest.mark.parametrize("record", [TEST_RECORDS[0]])
@pytest.mark.parametrize("encrypt", [True, False])
@pytest.mark.error_path
def test_error_on_popapi_error(client, record, encrypt):
    mock_backend()
    stored_record = dict(record)
    if encrypt:
        stored_record = client(encrypt).encrypt_record(stored_record)

    httpretty.register_uri(
        httpretty.POST, POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/find", status=400
    )
    httpretty.register_uri(
        httpretty.POST, POPAPI_URL + "/v2/storage/records/" + COUNTRY, status=400
    )
    httpretty.register_uri(
        httpretty.GET,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/" + stored_record["key"],
        status=400,
    )
    httpretty.register_uri(
        httpretty.DELETE,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/" + stored_record["key"],
        status=400,
    )

    client(encrypt).write.when.called_with(country=COUNTRY, **record).should.have.raised(
        incountry.StorageServerError
    )
    client(encrypt).read.when.called_with(country=COUNTRY, **record).should.have.raised(
        incountry.StorageServerError
    )
    client(encrypt).delete.when.called_with(country=COUNTRY, **record).should.have.raised(
        incountry.StorageServerError
    )
    client(encrypt).find.when.called_with(country=COUNTRY, **record).should.have.raised(
        incountry.StorageServerError
    )
    client(encrypt).find_one.when.called_with(country=COUNTRY, **record).should.have.raised(
        incountry.StorageServerError
    )


@pytest.mark.parametrize("record", [{}, {"country": COUNTRY}, {"key": "key1"}])
@pytest.mark.error_path
def test_error_write_insufficient_args(client, record):
    client().write.when.called_with(**record).should.have.raised(Exception)


@pytest.mark.parametrize("record", [{"country": None, "key": None}])
@pytest.mark.error_path
def test_error_read_insufficient_args(client, record):
    client().read.when.called_with(**record).should.have.raised(Exception)


@pytest.mark.parametrize("record", [{}, {"country": COUNTRY}, {"key": "key1"}])
@pytest.mark.error_path
def test_error_delete_insufficient_args(client, record):
    client().delete.when.called_with(**record).should.have.raised(Exception)


@pytest.mark.parametrize("record", [{}])
@pytest.mark.error_path
def test_error_find_insufficient_args(client, record):
    client().find.when.called_with(**record).should.have.raised(Exception)


@pytest.mark.parametrize("record", [{}])
@pytest.mark.error_path
def test_error_find_one_insufficient_args(client, record):
    client().find_one.when.called_with(**record).should.have.raised(Exception)
