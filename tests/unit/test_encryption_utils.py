import pytest
import sure

from incountry import (
    decrypt_record,
    encrypt_record,
    hash_custom_key,
    InCrypto,
)

from incountry.encryption_utils import is_json


@pytest.mark.parametrize(
    "crypto,value,salt,error",
    [
        (None, "test", "test", "'crypto' argument should be an instance of InCrypto. Got <class 'NoneType'>"),
        (InCrypto(), None, "test", "'value' argument should be of type string. Got <class 'NoneType'>"),
        (InCrypto(), "test", None, "'salt' argument should be of type string. Got <class 'NoneType'>"),
    ],
)
@pytest.mark.happy_path
def test_hash_custom_key_args_validation(crypto, value, salt, error):
    hash_custom_key.when.called_with(crypto, value, salt).should.have.raised(Exception, error)


@pytest.mark.parametrize(
    "crypto,record,salt,error",
    [
        (None, {}, "test", "'crypto' argument should be an instance of InCrypto. Got <class 'NoneType'>"),
        (InCrypto(), {}, None, "'salt' argument should be of type string. Got <class 'NoneType'>"),
    ],
)
@pytest.mark.happy_path
def test_encrypt_record_args_validation(crypto, record, salt, error):
    encrypt_record.when.called_with(crypto, record, salt).should.have.raised(Exception, error)


@pytest.mark.parametrize(
    "crypto,record,error", [(None, {}, "'crypto' argument should be an instance of InCrypto. Got <class 'NoneType'>")],
)
@pytest.mark.happy_path
def test_decrypt_record_args_validation(crypto, record, error):
    decrypt_record.when.called_with(crypto, record).should.have.raised(Exception, error)


@pytest.mark.parametrize(
    "data,result", [("test", False), ('"test"', True), ("1", True), ('{"test": 42}', True), ("42", True)],
)
@pytest.mark.happy_path
def test_is_json(data, result):
    assert is_json(data) == result
