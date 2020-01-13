import uuid
from random import randint
import operator
from incountry import StorageServerError, Storage
import sure
import pytest
from typing import Dict, List, Any

COUNTRIES = ["se"]


@pytest.mark.parametrize(
    "encrypt", [True, False], ids=["encrypted", "not encrypted"]
)
@pytest.mark.parametrize(
    "data",
    [
        {
            "key": uuid.uuid4().hex,
            "body": uuid.uuid4().hex,
            "profile_key": uuid.uuid4().hex,
            "range_key": randint(-(2 ** 63), 2 ** 62),
            "key2": uuid.uuid4().hex,
            "key3": uuid.uuid4().hex,
        },
        {
            "key": uuid.uuid4().hex,
            "body": uuid.uuid4().hex,
            "profile_key": uuid.uuid4().hex,
        },
        {"key": uuid.uuid4().hex},
    ],
    ids=[
        "all the fields in record",
        "key, body, profile_key in record",
        "only key in record",
    ],
)
@pytest.mark.parametrize("country", COUNTRIES)
def test_write_record(
    storage: Storage, country: str, encrypt: bool, data: Dict[str, Any]
) -> None:
    write_response = storage.write(country=country, **data)
    write_response.should_not.be.none
    write_response.should.have.key("record")
    write_response["record"].should.be.equal(data)


@pytest.mark.parametrize(
    "encrypt", [True, False], ids=["encrypted", "not encrypted"]
)
@pytest.mark.parametrize("country", COUNTRIES)
def test_write_with_the_same_key_updates_record(
    storage: Storage, country: str, encrypt: bool
) -> None:
    record_key = uuid.uuid4().hex
    record = {
        "key": record_key,
        "key2": "some key2",
        "key3": "some key3",
        "profile_key": "some profile_key",
        "body": "some body",
        "range_key": 42,
    }
    write_response = storage.write(country=country, **record)
    write_response["record"].should.be.equal(record)

    updated_record = {
        "key": record_key,
        "key2": "new key2",
        "key3": "new key3",
        "profile_key": "new profile_key",
        "body": "new body",
        "range_key": 333,
    }
    write_response = storage.write(country=country, **updated_record)
    write_response.should_not.be.none
    write_response.should.have.key("record")
    write_response["record"].should.be.equal(updated_record)


@pytest.mark.parametrize("country", COUNTRIES)
@pytest.mark.parametrize(
    "encrypt", [True, False], ids=["encrypted", "not encrypted"]
)
def test_read_record(storage: Storage, country: str, encrypt: bool) -> None:
    record = {
        "key": "unique key",
        "key2": "some key2",
        "key3": "some key3",
        "profile_key": "some profile_key",
        "body": "some body",
        "range_key": 42,
    }
    storage.write(country=country, **record)

    read_response = storage.read(country=country, key=record["key"])
    read_response.should.be.a("dict")
    read_response.should.have.key("record")
    for key in record:
        read_response["record"][key].should.be.equal(record[key])


@pytest.mark.parametrize("country", COUNTRIES)
@pytest.mark.parametrize(
    "encrypt", [True, False], ids=["encrypted", "not encrypted"]
)
def test_read_not_existing_record(
    storage: Storage, country: str, encrypt: bool
) -> None:
    record_key = uuid.uuid4().hex
    storage.read.when.called_with(
        country=country, key=record_key
    ).should.have.raised(StorageServerError)


@pytest.mark.parametrize("country", COUNTRIES)
@pytest.mark.parametrize(
    "encrypt", [True, False], ids=["encrypted", "not encrypted"]
)
def test_delete_record(storage: Storage, country: str, encrypt: bool) -> None:
    key1 = uuid.uuid4().hex

    storage.write(country=country, key=key1, body="some body")

    r = storage.read(country=country, key=key1)
    assert r is not None

    delete_response = storage.delete(country=country, key=key1)
    delete_response.should.be.a("dict")
    delete_response.should.have.key("success")
    delete_response["success"].should.be(True)

    storage.read.when.called_with(
        country=country, key=key1
    ).should.have.raised(StorageServerError)


@pytest.mark.parametrize("country", COUNTRIES)
@pytest.mark.parametrize(
    "encrypt", [True, False], ids=["encrypted", "not encrypted"]
)
def test_delete_not_existing_record(
    storage: Storage, country: str, encrypt: bool
) -> None:
    record_key = uuid.uuid4().hex
    storage.delete.when.called_with(
        country=country, key=record_key
    ).should.have.raised(StorageServerError)


@pytest.mark.parametrize("country", COUNTRIES)
@pytest.mark.parametrize(
    "encrypt", [True, False], ids=["encrypted", "not encrypted"]
)
def test_batch_write_records(
    storage: Storage, country: str, encrypt: bool
) -> None:
    records = [
        {
            key: uuid.uuid4().hex
            if key != "range_key"
            else randint(-(2 ** 63), 2 ** 63 - 1)
            for key in [
                "key",
                "key2",
                "key3",
                "profile_key",
                "range_key",
                "body",
            ]
        }
        for _ in range(3)
    ]
    written = storage.batch_write(country=country, records=records)

    written.should.be.a("dict")
    written.should.have.key("records")
    written["records"].should.be.a("list")
    written["records"].should.equal(records)


@pytest.mark.parametrize(
    "update_by",
    ["key", "profile_key"],
    ids=["update by key", "update by profile key"],
)
@pytest.mark.parametrize(
    "encrypt", [True, False], ids=["encrypted", "not encrypted"]
)
@pytest.mark.parametrize("country", COUNTRIES)
def test_update_one(
    storage: Storage, encrypt: bool, update_by: str, country: str
) -> None:
    record = {"key": uuid.uuid4().hex, "profile_key": uuid.uuid4().hex}
    storage.write(country=country, **record)

    updated_sample = storage.update_one(
        filters={update_by: record[update_by]}, country=country, range_key=333
    )

    for key in record:
        updated_sample["record"][key].should.be.equal(record[key])
    updated_sample["record"]["range_key"].should.be.equal(333)

    find_updated_record = storage.find(country=country, key=record["key"])
    len(find_updated_record["records"]).should.be.equal(1)
    find_updated_record["records"][0]["range_key"].should.be.equal(333)


@pytest.mark.parametrize(
    "key", ["key", "key2", "key3", "profile_key", "range_key"]
)
@pytest.mark.parametrize(
    "encrypt", [True, False], ids=["encrypted", "not encrypted"]
)
@pytest.mark.parametrize("country", COUNTRIES)
def test_find_by_one_key(
    storage: Storage,
    encrypt: bool,
    country: str,
    expected_records: List[Dict],
    key: str,
) -> None:
    key_value = expected_records[0][key]
    search = {key: key_value}
    find_result = storage.find(country=country, **search)
    find_result.should.be.a("dict")
    find_result.should.have.key("records")
    find_result.should.have.key("meta")
    actual_keys = [record[key] for record in find_result["records"]]
    expected_keys = [
        record[key] for record in expected_records if record[key] == key_value
    ]
    expected_keys.should.equal(actual_keys)


@pytest.mark.parametrize(
    "key", ["key", "key2", "key3", "profile_key", "range_key"]
)
@pytest.mark.parametrize(
    "encrypt", [True, False], ids=["encrypted", "not encrypted"]
)
@pytest.mark.parametrize("country", COUNTRIES)
def test_find_by_list_of_keys(
    storage: Storage,
    encrypt: bool,
    country: str,
    expected_records: List[Dict],
    key: str,
) -> None:
    key_values = [record[key] for record in expected_records]
    search = {key: key_values}
    find_result = storage.find(country=country, **search)
    find_result.should.be.a("dict")
    find_result.should.have.key("records")
    find_result.should.have.key("meta")
    actual_keys = {record[key] for record in find_result["records"]}
    expected_keys = {record[key] for record in expected_records}
    expected_keys.should.equal(actual_keys)


@pytest.mark.parametrize("range_operator", ["$gt", "$lt", "$gte", "$lte"])
@pytest.mark.parametrize(
    "encrypt", [True, False], ids=["encrypted", "not encrypted"]
)
@pytest.mark.parametrize("country", COUNTRIES)
def test_find_by_range_key_gt_lt(
    storage: Storage, encrypt: bool, country: str, range_operator: str
) -> None:
    records = [
        {"key": uuid.uuid4().hex, "range_key": i} for i in [-1000, 0, 1000]
    ]
    for record in records:
        storage.write(country=country, **record)

    record_keys = [record["key"] for record in records]
    find_result = storage.find(
        country=country, key=record_keys, range_key={range_operator: 0}
    )

    op = {
        "$gt": operator.gt,
        "$gte": operator.ge,
        "$lt": operator.lt,
        "$lte": operator.le,
    }
    actual_records = find_result["records"]
    len(actual_records).should.be.greater_than(0)
    for _ in actual_records:
        for _, value in record.items():
            if value is int:
                assert op[range_operator](value, 0)


@pytest.mark.parametrize(
    "encrypt", [True, False], ids=["encrypted", "not encrypted"]
)
@pytest.mark.parametrize("country", COUNTRIES)
def test_find_not_existing_record(
    storage: Storage, encrypt: bool, country: str
) -> None:
    find_nothing = storage.find(country=country, key="Not existing key")
    len(find_nothing["records"]).should.be.equal(0)
    find_nothing["meta"]["total"].should.be.equal(0)


@pytest.mark.parametrize("number_of_records", [10])
@pytest.mark.parametrize(
    "limit", [1, 5, 10], ids=["limit_1", "limit_5", "limit_10"],
)
@pytest.mark.parametrize(
    "encrypt", [True, False], ids=["encrypted", "not encrypted"]
)
@pytest.mark.parametrize("country", COUNTRIES)
def test_find_limit_works(
    encrypt: bool,
    storage: Storage,
    country: str,
    limit: int,
    expected_records: List[Dict],
    number_of_records: int,
) -> None:
    record_keys = [record["key"] for record in expected_records]

    find_limit = storage.find(country=country, key=record_keys, limit=limit)
    find_limit["meta"]["limit"].should.be.equal(limit)
    len(find_limit["records"]).should.be.equal(limit)
    found_keys = [record["key"] for record in find_limit["records"]]
    assert set(found_keys).issubset(set(record_keys))


@pytest.mark.parametrize("number_of_records", [10])
@pytest.mark.parametrize(
    "offset",
    [0, 1, 5, 10],
    ids=["offset_0", "offset_1", "offset_5", "offset_100"],
)
@pytest.mark.parametrize(
    "encrypt", [True, False], ids=["encrypted", "not encrypted"]
)
@pytest.mark.parametrize("country", COUNTRIES)
def test_find_offset_works(
    encrypt: bool,
    storage: Storage,
    country: str,
    offset: int,
    expected_records: List[Dict],
    number_of_records: int,
) -> None:
    record_keys = [record["key"] for record in expected_records]
    remains_after_offset = max(10 - offset, 0)

    find_offset = storage.find(country=country, key=record_keys, offset=offset)
    len(find_offset["records"]).should.be.equal(remains_after_offset)
    find_offset["meta"]["offset"].should.be.equal(offset)
    found_keys = [record["key"] for record in find_offset["records"]]
    assert set(found_keys).issubset(set(record_keys))


@pytest.mark.parametrize(
    "search_key", ["key", "profile_key", "range_key", "key2", "key3"]
)
@pytest.mark.parametrize(
    "encrypt", [True, False], ids=["encrypted", "not encrypted"]
)
@pytest.mark.parametrize("country", COUNTRIES)
def test_find_one(
    storage: Storage,
    encrypt: bool,
    search_key: str,
    country: str,
    expected_records: List[Dict],
) -> None:
    search = {search_key: expected_records[0][search_key]}
    find_one_record = storage.find_one(country=country, **search)
    find_one_record.should_not.be.none
    find_one_record.should.be.a("dict")
    find_one_record.should.have.key("record")
    find_one_record["record"][search_key].should.be.equal(
        expected_records[0][search_key]
    )


@pytest.mark.parametrize(
    "encrypt", [True, False], ids=["encrypted", "not encrypted"]
)
@pytest.mark.parametrize("country", COUNTRIES)
def test_find_one_empty_response(
    storage: Storage, encrypt: bool, country: str
) -> None:
    r = storage.find_one(country=country, key=uuid.uuid4().hex)
    r.should.equal(None)
