import sure
import pytest
from incountry import StorageServerError, StorageClientError
import re
from pytest_testrail.plugin import pytestrail


@pytestrail.case("C91408")
@pytest.mark.parametrize("encrypt", [False], ids=["not encrypted"])
@pytest.mark.parametrize("country", ["us", "in"])
def test_migrate_should_raise_error_without_encryption(storage, country, encrypt):

    storage.migrate.when.called_with(country).should.have.raised(StorageClientError,
                                                                 re.compile(
                                                                     r"Migration not supported when encryption is off"
                                                                 )
                                                                 )


@pytestrail.case("C91409")
@pytest.mark.parametrize("encrypt", [True], ids=["encrypted"])
@pytest.mark.parametrize("country", ["us"])
def test_migrate_works_with_encryption(storage, country, encrypt):
    storage.migrate.when.called_with(country).should_not.have.raised(StorageClientError)

    migration_result = storage.migrate(country=country)
    migration_result.should.contain("migrated", "total_left")