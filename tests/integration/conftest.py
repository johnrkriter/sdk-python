from incountry import SecretKeyAccessor, Storage
import os
import pytest
from random import randint
from typing import List, Dict
import uuid


@pytest.fixture
def storage(encrypt: bool) -> Storage:
    """Creating storage"""
    password = os.environ.get("PASSWORD")
    secret_key_accessor = SecretKeyAccessor(lambda: password)

    if encrypt:
        storage = Storage(
            encrypt=True, debug=True, secret_key_accessor=secret_key_accessor
        )
    else:
        storage = Storage(encrypt=False, debug=True)

    yield storage


def create_records(number_of_records: int) -> List[Dict]:
    return [
        {
            "key": uuid.uuid4().hex,
            "key2": uuid.uuid4().hex,
            "key3": uuid.uuid4().hex,
            "profile_key": uuid.uuid4().hex,
            "range_key": randint(-(2 ** 63), 2 ** 63 - 1),
            "body": uuid.uuid4().hex,
        }
        for _ in range(number_of_records)
    ]


@pytest.fixture(autouse=True)
def number_of_records() -> int:
    yield 3


@pytest.fixture
def expected_records(storage: Storage, country: str, number_of_records: int):
    data = create_records(number_of_records)
    for record in data:
        assert "key" in record.keys()
        response = storage.write(country=country, **record)
        assert response["record"]["key"] == record["key"]
    yield data

    for record in data:
        key = record["key"]
        response = storage.delete(country=country, key=key)
        assert response == {"success": True}
