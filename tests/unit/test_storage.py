import pytest
from incountry import Storage, StorageServerError, StorageClientError, SecretKeyAccessor
import uuid
import json
import sure
import httpretty

POPAPI_URL = "https://popapi.com:8082"
COUNTRY = "us"
SECRET_KEY = "password"

TEST_RECORDS = [
    {"key": str(uuid.uuid1())},
    {"key": str(uuid.uuid1()), "body": "test"},
    {"key": str(uuid.uuid1()), "body": "test", "key2": "key2"},
    {"key": str(uuid.uuid1()), "body": "test", "key2": "key2", "key3": "key3"},
    {"key": str(uuid.uuid1()), "body": "test", "key2": "key2", "key3": "key3", "profile_key": "profile_key"},
    {
        "key": str(uuid.uuid1()),
        "body": "test",
        "key2": "key2",
        "key3": "key3",
        "profile_key": "profile_key",
        "range_key": 1,
    },
]


def omit(d, keys):
    if isinstance(keys, str):
        keys = [keys]
    return {x: d[x] for x in d if x not in keys}


def mock_backend():
    httpretty.register_uri(
        httpretty.GET,
        Storage.PORTALBACKEND_URI + "/countries",
        body=json.dumps({"countries": [{"id": "RU", "direct": True}, {"id": "AG", "direct": False}]}),
    )


def get_default_find_response(count, data, total=None):
    total = count if total is None else total
    return {
        "meta": {"total": total, "count": count, "limit": 100, "offset": 0},
        "data": data,
    }


@pytest.fixture()
def client():
    def cli(encrypt=True, endpoint=POPAPI_URL, secret_accessor=SecretKeyAccessor(lambda: SECRET_KEY)):
        return Storage(
            encrypt=encrypt,
            debug=True,
            environment_id="test",
            api_key="test",
            endpoint=endpoint,
            secret_key_accessor=secret_accessor,
        )

    return cli


@httpretty.activate
@pytest.mark.parametrize("record", TEST_RECORDS)
@pytest.mark.parametrize("encrypt", [True, False])
@pytest.mark.happy_path
def test_write(client, record, encrypt):
    mock_backend()
    httpretty.register_uri(httpretty.POST, POPAPI_URL + "/v2/storage/records/" + COUNTRY, body="OK")

    write_res = client(encrypt).write(country=COUNTRY, **record)
    write_res.should.have.key("record")
    write_res["record"].should.be.equal(record)

    received_record = json.loads(httpretty.last_request().body)

    if record.get("range_key", None):
        assert received_record["range_key"] == record["range_key"]

    for k in ["body", "key", "key2", "key3", "profile_key"]:
        if record.get(k, None) and encrypt:
            assert received_record[k] != record[k]


@httpretty.activate
@pytest.mark.parametrize("record", TEST_RECORDS)
@pytest.mark.parametrize("encrypt", [True, False])
@pytest.mark.parametrize("keys_data", [{"currentVersion": 1, "secrets": [{"secret": SECRET_KEY, "version": 1}]}])
@pytest.mark.happy_path
def test_write_with_keys_data(client, record, encrypt, keys_data):
    mock_backend()
    httpretty.register_uri(httpretty.POST, POPAPI_URL + "/v2/storage/records/" + COUNTRY, body="OK")

    secret_accessor = SecretKeyAccessor(lambda: keys_data)

    write_res = client(encrypt=encrypt, secret_accessor=secret_accessor).write(country=COUNTRY, **record)
    write_res.should.have.key("record")
    write_res["record"].should.be.equal(record)

    received_record = json.loads(httpretty.last_request().body)

    if encrypt:
        assert received_record.get("version") == keys_data.get("currentVersion")
    else:
        assert received_record.get("version") == SecretKeyAccessor.DEFAULT_VERSION

    if record.get("range_key", None):
        assert received_record["range_key"] == record["range_key"]

    for k in ["body", "key", "key2", "key3", "profile_key"]:
        if record.get(k, None):
            assert received_record[k] != record[k]


@httpretty.activate
@pytest.mark.parametrize("records", [TEST_RECORDS])
@pytest.mark.parametrize("encrypt", [True, False])
@pytest.mark.happy_path
def test_batch_write(client, records, encrypt):
    mock_backend()
    httpretty.register_uri(httpretty.POST, POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/batchWrite", body="OK")

    batch_res = client(encrypt).batch_write(country=COUNTRY, records=records)
    batch_res.should.have.key("records")
    batch_res["records"].should.be.equal(records)

    received_records = json.loads(httpretty.last_request().body)
    received_records.should.have.key("records")

    for received_record in received_records["records"]:
        original_record = next(
            (
                item
                for item in records
                if (encrypt and client(encrypt).hash_custom_key(item.get("key")) == received_record.get("key"))
                or (not encrypt and item.get("key") == received_record.get("key"))
            ),
            None,
        )
        if original_record.get("range_key", None):
            assert received_record["range_key"] == original_record["range_key"]

        for k in ["body", "key", "key2", "key3", "profile_key"]:
            if original_record.get(k, None) and encrypt:
                assert received_record[k] != original_record[k]
            if original_record.get(k, None) and not encrypt:
                assert received_record[k] == original_record[k]


@httpretty.activate
@pytest.mark.parametrize("record", TEST_RECORDS)
@pytest.mark.parametrize("encrypt", [True, False])
@pytest.mark.happy_path
def test_read(client, record, encrypt):
    stored_record = client(encrypt).encrypt_record(dict(record))

    httpretty.register_uri(
        httpretty.GET,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/" + stored_record["key"],
        body=json.dumps(stored_record),
    )

    read_response = client(encrypt).read(country=COUNTRY, key=record["key"])
    read_response.should.have.key("record")
    omit(read_response["record"], "version").should.be.equal(record)


@httpretty.activate
@pytest.mark.parametrize(
    "record_1",
    [
        {
            "key": str(uuid.uuid1()),
            "body": "test_1",
            "key2": "key2_1",
            "key3": "key3_1",
            "profile_key": "profile_key_1",
            "range_key": 1,
        }
    ],
)
@pytest.mark.parametrize(
    "record_2",
    [
        {
            "key": str(uuid.uuid1()),
            "body": "test_2",
            "key2": "key2_2",
            "key3": "key3_2",
            "profile_key": "profile_key_2",
            "range_key": 2,
        }
    ],
)
@pytest.mark.parametrize("encrypt", [True, False])
@pytest.mark.parametrize("keys_data_old", [{"currentVersion": 0, "secrets": [{"secret": SECRET_KEY, "version": 0}]}])
@pytest.mark.parametrize(
    "keys_data_new",
    [
        {
            "currentVersion": 1,
            "secrets": [{"secret": SECRET_KEY, "version": 0}, {"secret": SECRET_KEY + "1", "version": 1}],
        }
    ],
)
@pytest.mark.happy_path
def test_read_multiple_keys(client, record_1, record_2, encrypt, keys_data_old, keys_data_new):
    secret_accessor_old = SecretKeyAccessor(lambda: keys_data_old)
    secret_accessor_new = SecretKeyAccessor(lambda: keys_data_new)

    client_old = client(encrypt=encrypt, secret_accessor=secret_accessor_old)
    client_new = client(encrypt=encrypt, secret_accessor=secret_accessor_new)

    stored_record_1 = client_old.encrypt_record(dict(record_1))
    stored_record_2 = client_new.encrypt_record(dict(record_2))

    httpretty.register_uri(
        httpretty.GET,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/" + stored_record_1["key"],
        body=json.dumps(stored_record_1),
    )

    httpretty.register_uri(
        httpretty.GET,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/" + stored_record_2["key"],
        body=json.dumps(stored_record_2),
    )

    record_1_response = client_new.read(country=COUNTRY, key=record_1["key"])
    record_2_response = client_new.read(country=COUNTRY, key=record_2["key"])

    if encrypt:
        assert record_1_response["record"]["version"] == keys_data_old.get("currentVersion")
        assert record_2_response["record"]["version"] == keys_data_new.get("currentVersion")
    else:
        assert record_1_response["record"]["version"] == SecretKeyAccessor.DEFAULT_VERSION
        assert record_2_response["record"]["version"] == SecretKeyAccessor.DEFAULT_VERSION

    omit(record_1_response["record"], "version").should.be.equal(record_1)
    omit(record_2_response["record"], "version").should.be.equal(record_2)


@httpretty.activate
@pytest.mark.parametrize("record", TEST_RECORDS)
@pytest.mark.parametrize("encrypt", [True, False])
@pytest.mark.happy_path
def test_delete(client, record, encrypt):
    response = {"result": "OK"}

    stored_record = dict(record)
    stored_record = client(encrypt).encrypt_record(stored_record)

    httpretty.register_uri(
        httpretty.DELETE,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/" + stored_record["key"],
        body=json.dumps(response),
    )

    delete_res = client(encrypt).delete(country=COUNTRY, key=record["key"])
    delete_res.should.be.equal({"success": True})


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
    enc_data = [client(encrypt).encrypt_record(dict(x)) for x in records]

    httpretty.register_uri(
        httpretty.POST,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/find",
        body=json.dumps(get_default_find_response(len(enc_data), enc_data)),
    )

    find_response = client(encrypt).find(country=COUNTRY, **query)

    received_record = json.loads(httpretty.last_request().body)
    received_record.should.be.a(dict)
    received_record.should.have.key("filter")
    received_record.should.have.key("options")
    received_record["options"].should.equal(
        {"limit": query.get("limit", Storage.FIND_LIMIT), "offset": query.get("offset", 0)}
    )

    if query.get("range_key", None):
        assert received_record["filter"]["range_key"] == query["range_key"]

    for k in ["key", "key2", "key3", "profile_key"]:
        if query.get(k, None):
            assert received_record["filter"][k] != query[k]

    find_response.should.be.a(dict)

    for data_record in find_response.get("records"):
        match = next(r for r in records if data_record["key"] == r["key"])
        for k in ["body", "key", "key2", "key3", "profile_key"]:
            if match.get(k, None):
                assert data_record[k] == match[k]


@httpretty.activate
@pytest.mark.parametrize(
    "query,records", [({"key": "key1"}, TEST_RECORDS)],
)
@pytest.mark.parametrize("encrypt", [True, False])
@pytest.mark.happy_path
def test_find_enc_and_non_enc(client, query, records, encrypt):
    records_to_enc = records[len(records) // 2 :]
    records_to_not_enc = records[: len(records) // 2]
    stored_enc_data = [client(encrypt=True).encrypt_record(dict(x)) for x in records_to_enc]
    stored_non_enc_data = [client(encrypt=False).encrypt_record(dict(x)) for x in records_to_not_enc]
    stored_data = stored_enc_data + stored_non_enc_data

    httpretty.register_uri(
        httpretty.POST,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/find",
        body=json.dumps(get_default_find_response(len(stored_data), stored_data)),
    )

    find_response = client(encrypt).find(country=COUNTRY, **query)

    encrypted_records_received = []
    for data_record in find_response.get("records"):
        match = next((r for r in records if data_record["key"] == r["key"]), None)
        if match:
            for k in ["body", "key", "key2", "key3", "profile_key"]:
                if match.get(k, None):
                    assert data_record[k] == match[k]
        else:
            encrypted_records_received.append(data_record)

    if encrypt:
        assert len(encrypted_records_received) == 0
    else:
        assert len(encrypted_records_received) == len(records_to_enc)


@httpretty.activate
@pytest.mark.parametrize(
    "query,record",
    [
        ({"key": "key1"}, {"country": COUNTRY, "key": "key1", "version": 0}),
        ({"key": "key2"}, {"country": COUNTRY, "key": "key2", "body": "test", "version": 0}),
        ({"key": "key3"}, None),
    ],
)
@pytest.mark.parametrize("encrypt", [True, False])
@pytest.mark.happy_path
def test_find_one(client, query, record, encrypt):
    stored_record = None
    if record:
        stored_record = dict(record)
        stored_record = client(encrypt).encrypt_record(stored_record)

    count = 0 if stored_record is None else 1
    data = [] if stored_record is None else [stored_record]

    httpretty.register_uri(
        httpretty.POST,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/find",
        body=json.dumps(get_default_find_response(count, data)),
    )

    find_one_response = client(encrypt).find_one(country=COUNTRY, **query)
    if record:
        find_one_response.should.have.key("record")
        find_one_response["record"].should.equal(record)
    else:
        find_one_response.should.equal(record)


@httpretty.activate
@pytest.mark.parametrize("records", [TEST_RECORDS])
@pytest.mark.parametrize("keys_data_old", [{"currentVersion": 0, "secrets": [{"secret": SECRET_KEY, "version": 0}]}])
@pytest.mark.parametrize(
    "keys_data_new",
    [
        {
            "currentVersion": 1,
            "secrets": [{"secret": SECRET_KEY, "version": 0}, {"secret": SECRET_KEY + "1", "version": 1}],
        }
    ],
)
@pytest.mark.happy_path
def test_migrate(client, records, keys_data_old, keys_data_new):
    secret_accessor_old = SecretKeyAccessor(lambda: keys_data_old)
    secret_accessor_new = SecretKeyAccessor(lambda: keys_data_new)

    stored_records = [
        client(encrypt=True, secret_accessor=secret_accessor_old).encrypt_record(dict(x)) for x in records
    ]

    total_stored = len(stored_records) + 1

    httpretty.register_uri(
        httpretty.POST,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/find",
        body=json.dumps(get_default_find_response(len(stored_records), stored_records, total_stored)),
    )

    httpretty.register_uri(httpretty.POST, POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/batchWrite", body="OK")

    migrate_res = client(encrypt=True, secret_accessor=secret_accessor_new).migrate(country=COUNTRY)

    assert migrate_res["total_left"] == total_stored - len(stored_records)
    assert migrate_res["migrated"] == len(stored_records)

    received_records = json.loads(httpretty.last_request().body)
    for received_record in received_records["records"]:
        original_stored_record = next(
            (item for item in stored_records if item.get("key") == received_record.get("key")), None
        )

        assert original_stored_record is not None

        assert original_stored_record.get("version") != received_record.get("version")
        assert received_record.get("version") == keys_data_new.get("currentVersion")

        for k in ["key", "key2", "key3", "profile_key", "range_key"]:
            if original_stored_record.get(k, None):
                assert received_record[k] == original_stored_record[k]

        if original_stored_record.get("body", None):
            assert received_record["body"] != original_stored_record["body"]


@httpretty.activate
@pytest.mark.parametrize("record", [TEST_RECORDS[-1]])
@pytest.mark.parametrize("update_key", ["key", "key2", "key3", "profile_key", "range_key"])
@pytest.mark.parametrize("encrypt", [True, False])
@pytest.mark.happy_path
def test_update(client, record, update_key, encrypt):
    stored_record = client(encrypt).encrypt_record(dict(record))

    httpretty.register_uri(httpretty.POST, POPAPI_URL + "/v2/storage/records/" + COUNTRY, body="OK")
    httpretty.register_uri(
        httpretty.POST,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/find",
        body=json.dumps(get_default_find_response(1, [stored_record])),
    )

    data_for_update = dict(
        [(update_key, record[update_key] + 1 if isinstance(record[update_key], int) else record[update_key] + "1",)]
    )

    update_res = client(encrypt).update_one(
        country=COUNTRY, filters=dict([(update_key, record[update_key])]), **data_for_update
    )
    update_res.should.have.key("record")
    received_record = json.loads(httpretty.last_request().body)

    for k in ["body", "key", "key2", "key3", "profile_key", "range_key"]:
        if k == update_key:
            assert update_res["record"][k] == data_for_update[k]
        else:
            assert update_res["record"][k] == record[k]

    if record.get("range_key", None) and update_key != "range_key":
        assert received_record["range_key"] == record["range_key"]

    if record.get("range_key", None) and update_key == "range_key":
        assert received_record["range_key"] == data_for_update["range_key"]

    for k in ["body", "key", "key2", "key3", "profile_key"]:
        if record.get(k, None):
            assert received_record[k] != record[k]


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
    stored_record = client().encrypt_record(dict(record))

    midpop_ids = [c["id"].lower() for c in countries if c["direct"]]
    is_midpop = country in midpop_ids
    endpoint = Storage.get_midpop_url(country) if is_midpop else Storage.DEFAULT_ENDPOINT

    countries_url = Storage.PORTALBACKEND_URI + "/countries"
    httpretty.register_uri(httpretty.GET, countries_url, body=json.dumps({"countries": countries}))

    read_url = endpoint + "/v2/storage/records/" + country + "/" + stored_record["key"]
    httpretty.register_uri(httpretty.GET, read_url, body=json.dumps(record))

    client(endpoint=None).read(country=country, key=record["key"])

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
    stored_record = client().encrypt_record(dict(record))
    read_url = POPAPI_URL + "/v2/storage/records/" + country + "/" + stored_record["key"]
    httpretty.register_uri(httpretty.GET, read_url, body=json.dumps(stored_record))

    client(endpoint=POPAPI_URL).read(country=country, key=record["key"])

    latest_request = httpretty.HTTPretty.last_request
    latest_request_url = "https://" + latest_request.headers.get("Host", "") + latest_request.path

    assert latest_request_url == read_url


@httpretty.activate
@pytest.mark.parametrize("record", [TEST_RECORDS[0]])
@pytest.mark.parametrize("encrypt", [True, False])
@pytest.mark.error_path
def test_read_not_found(client, record, encrypt):
    stored_record = dict(record)
    stored_record = client(encrypt).encrypt_record(stored_record)

    httpretty.register_uri(
        httpretty.GET, POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/" + stored_record["key"], status=404,
    )

    client(encrypt).read.when.called_with(country=COUNTRY, key=record["key"]).should.throw(StorageServerError)


@httpretty.activate
@pytest.mark.parametrize(
    "query", [{"key": "key1", "limit": -1}, {"key": "key1", "limit": 101}, {"key": "key1", "limit": 1, "offset": -1}],
)
@pytest.mark.error_path
def test_find_error(client, query):
    httpretty.register_uri(
        httpretty.POST,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/find",
        body=json.dumps(get_default_find_response(0, [])),
    )

    client().find.when.called_with(country=COUNTRY, **query).should.have.raised(StorageClientError)


@httpretty.activate
@pytest.mark.parametrize("records", [[TEST_RECORDS[0], TEST_RECORDS[1]], []])
@pytest.mark.parametrize("encrypt", [True, False])
@pytest.mark.error_path
def test_update_error(client, records, encrypt):
    enc_data = [client(encrypt).encrypt_record(dict(x)) for x in records]

    httpretty.register_uri(
        httpretty.POST,
        POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/find",
        body=json.dumps(get_default_find_response(len(enc_data), enc_data)),
    )

    client(encrypt).update_one.when.called_with(
        country=COUNTRY, filters={"key": "key1"}, **{"key2": "key2"}
    ).should.have.raised(StorageServerError)


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
    Storage.when.called_with(**kwargs).should.have.raised(Exception)


@httpretty.activate
@pytest.mark.parametrize("record", [{"key": str(uuid.uuid1())}])
@pytest.mark.parametrize("encrypt", [True, False])
@pytest.mark.error_path
def test_error_on_popapi_error(client, record, encrypt):
    mock_backend()
    stored_record = client(encrypt).encrypt_record(dict(record))

    httpretty.register_uri(httpretty.POST, POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/find", status=400)
    httpretty.register_uri(httpretty.POST, POPAPI_URL + "/v2/storage/records/" + COUNTRY, status=400)
    httpretty.register_uri(
        httpretty.GET, POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/" + stored_record["key"], status=400,
    )
    httpretty.register_uri(
        httpretty.DELETE, POPAPI_URL + "/v2/storage/records/" + COUNTRY + "/" + stored_record["key"], status=400,
    )

    client(encrypt).write.when.called_with(country=COUNTRY, **record).should.have.raised(StorageServerError)
    client(encrypt).read.when.called_with(country=COUNTRY, **record).should.have.raised(StorageServerError)
    client(encrypt).delete.when.called_with(country=COUNTRY, **record).should.have.raised(StorageServerError)
    client(encrypt).find.when.called_with(country=COUNTRY, **record).should.have.raised(StorageServerError)
    client(encrypt).find_one.when.called_with(country=COUNTRY, **record).should.have.raised(StorageServerError)


@pytest.mark.parametrize("record", [{}, {"country": COUNTRY}, {"key": "key1"}])
@pytest.mark.error_path
def test_error_write_insufficient_args(client, record):
    client().write.when.called_with(**record).should.have.raised(Exception)


@pytest.mark.parametrize("records", [[], [{}]])
@pytest.mark.error_path
def test_error_batch_write_invalid_records(client, records):
    client().batch_write.when.called_with(country=COUNTRY, records=records).should.have.raised(StorageClientError)


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


@pytest.mark.error_path
def test_error_migrate_without_encryption(client):
    client(encrypt=False).migrate.when.called_with(country=COUNTRY).should.have.raised(StorageClientError)
