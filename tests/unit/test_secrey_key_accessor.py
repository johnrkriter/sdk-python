import pytest
import sure


from incountry import SecretKeyAccessor, SecretKeyAccessorException


@pytest.mark.parametrize("password", ["password"])
@pytest.mark.happy_path
def test_get_key_old(password):
    secret_accessor = SecretKeyAccessor(lambda: password)
    [secret, key_version] = secret_accessor.get_key()
    assert secret == password
    assert key_version == SecretKeyAccessor.DEFAULT_VERSION


@pytest.mark.parametrize(
    "keys_data, proper_version, proper_key",
    [
        (
            {
                "currentKeyVersion": 1,
                "keys": [
                    {"key": "password0", "keyVersion": 0},
                    {"key": "password1", "keyVersion": 1},
                ],
            },
            1,
            "password1",
        )
    ],
)
@pytest.mark.happy_path
def test_get_key(keys_data, proper_version, proper_key):
    secret_accessor = SecretKeyAccessor(lambda: keys_data)
    [secret, key_version] = secret_accessor.get_key()
    assert key_version == proper_version
    assert secret == proper_key


@pytest.mark.error_path
def test_non_callable_accessor_function():
    SecretKeyAccessor.when.called_with("password").should.have.raised(SecretKeyAccessorException)


@pytest.mark.error_path
def test_incorrect_version_requested():
    secret_accessor = SecretKeyAccessor(lambda: "some password")
    secret_accessor.get_key.when.called_with("non int").should.have.raised(
        SecretKeyAccessorException
    )


@pytest.mark.parametrize(
    "keys_data", [{"currentKeyVersion": 1, "keys": [{"key": "password", "keyVersion": 1}]}]
)
@pytest.mark.error_path
def test_non_existing_version_requested(keys_data):
    secret_accessor = SecretKeyAccessor(lambda: keys_data)
    secret_accessor.get_key.when.called_with(key_version=0).should.have.raised(
        SecretKeyAccessorException
    )


@pytest.mark.parametrize(
    "keys_data",
    [
        {"keys": [{"key": "password", "keyVersion": 1}]},
        {"currentKeyVersion": 1},
        {"currentKeyVersion": "1", "keys": [{"key": "password", "keyVersion": 1}]},
        {"currentKeyVersion": 1, "keys": [{"key": "password", "keyVersion": "1"}]},
        {"currentKeyVersion": 1, "keys": [{"key": 1, "keyVersion": 1}]},
        {"currentKeyVersion": 1, "keys": []},
    ],
)
@pytest.mark.error_path
def test_invalid_keys_object(keys_data):
    secret_accessor = SecretKeyAccessor(lambda: keys_data)
    secret_accessor.get_key.when.called_with(key_version=0).should.have.raised(
        SecretKeyAccessorException
    )
