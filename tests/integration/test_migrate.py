from typing import List, Dict
import re
import os
import sure
import pytest
from incountry import (
    StorageClientError,
    StorageServerError,
    Storage,
    SecretKeyAccessor,
)

API_KEY = os.environ.get("INT_INC_API_KEY")
ENV_ID = os.environ.get("INT_INC_ENVIRONMENT_ID")
ENDPOINT = os.environ.get("INT_INC_ENDPOINT")


@pytest.mark.parametrize("encrypt", [False], ids=["not encrypted"])
@pytest.mark.parametrize("country", ["us", "in"])
def test_migrate_should_raise_error_without_encryption(
    storage: Storage, encrypt: bool, country: str
) -> None:

    storage.migrate.when.called_with(country).should.have.raised(
        StorageClientError,
        re.compile(r"Migration not supported when encryption is off"),
    )


@pytest.mark.xfail
@pytest.mark.parametrize("encrypt", [True], ids=["encrypted"])
@pytest.mark.parametrize("country", ["us"])
def test_migrate_works_with_encryption(
    storage: Storage, encrypt: bool, country: str, expected_records: List[Dict]
) -> None:
    keys = {record["key"] for record in expected_records}
    find_all = storage.find(country=country)
    all_records = find_all["meta"]["total"]

    # There are records with ver 2, let's create storage with different version
    secrets_data = {
        "currentVersion": 3,
        "secrets": [
            {"secret": "new super secret", "version": 3},
            {"secret": "super secret", "version": 2},
        ],
    }
    new_storage = Storage(
        encrypt=True,
        debug=True,
        api_key=API_KEY,
        environment_id=ENV_ID,
        endpoint=ENDPOINT,
        secret_key_accessor=SecretKeyAccessor(lambda: secrets_data),
    )

    migration_result = new_storage.migrate(country=country)
    migration_result.should.have.key("migrated")
    migration_result.should.have.key("total_left")
    migration_result["migrated"].should.be.a("int")
    migration_result["total_left"].should.be.a("int")
    all_records.should.be.greater_than_or_equal_to(
        migration_result["migrated"]
    )

    nothing_lost = new_storage.find(country=country)
    found_keys = {record["key"] for record in nothing_lost["data"]}
    keys.should.be.equal(found_keys)
    nothing_lost["meta"]["total"].should.be.equal(all_records)

    read_record = new_storage.read(
        country=country, key=expected_records[0]["key"]
    )
    for key in expected_records[0]:
        read_record["record"][key].should.be.equal(expected_records[0][key])
    read_record["record"]["version"].should.be.equal(
        secrets_data["currentVersion"]
    )
    storage.read.when.called_with(
        country=country, key=expected_records[0]["key"]
    ).should.have.raised(StorageServerError)
