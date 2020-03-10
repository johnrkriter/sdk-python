import pytest
import sure  # noqa: F401


from incountry import SecretKeyAccessor, InCryptoException


@pytest.mark.parametrize("password", ["password"])
@pytest.mark.happy_path
def test_get_secret_old(password):
    secret_accessor = SecretKeyAccessor(lambda: password)
    [secret, secret_version, is_key] = secret_accessor.get_secret()
    assert secret == password
    assert secret_version == SecretKeyAccessor.DEFAULT_VERSION
    assert is_key is False


@pytest.mark.parametrize(
    "keys_data, proper_version, proper_key, proper_is_key",
    [
        (
            {
                "currentVersion": 2,
                "secrets": [{"secret": "password1", "version": 1}, {"secret": "password2", "version": 2}],
            },
            2,
            "password2",
            False,
        ),
        (
            {
                "currentVersion": 2,
                "secrets": [
                    {"secret": "password1", "version": 1},
                    {"secret": "12345678901234567890123456789012", "version": 2, "isKey": True},
                ],
            },
            2,
            "12345678901234567890123456789012",
            True,
        ),
    ],
)
@pytest.mark.happy_path
def test_get_secret(keys_data, proper_version, proper_key, proper_is_key):
    secret_accessor = SecretKeyAccessor(lambda: keys_data)
    [secret, secret_version, is_key] = secret_accessor.get_secret()
    assert secret_version == proper_version
    assert secret == proper_key
    assert is_key == proper_is_key


@pytest.mark.parametrize(
    "keys_data, proper_version, proper_key, proper_is_key",
    [
        (
            {
                "currentVersion": 2,
                "secrets": [{"secret": "password1", "version": 1}, {"secret": "1234", "version": 2, "isKey": True}],
            },
            2,
            "1234",
            True,
        ),
    ],
)
@pytest.mark.happy_path
def test_get_secret_ignoring_length_validation(keys_data, proper_version, proper_key, proper_is_key):
    secret_accessor = SecretKeyAccessor(lambda: keys_data)
    [secret, secret_version, is_key] = secret_accessor.get_secret(ignore_length_validation=True)
    assert secret_version == proper_version
    assert secret == proper_key
    assert is_key == proper_is_key


@pytest.mark.error_path
def test_non_callable_accessor_function():
    SecretKeyAccessor.when.called_with("password").should.have.raised(InCryptoException)


@pytest.mark.error_path
def test_incorrect_version_requested():
    secret_accessor = SecretKeyAccessor(lambda: "some password")
    secret_accessor.get_secret.when.called_with("non int").should.have.raised(InCryptoException)


@pytest.mark.parametrize("keys_data", [{"currentVersion": 1, "secrets": [{"secret": "password", "version": 1}]}])
@pytest.mark.error_path
def test_non_existing_version_requested(keys_data):
    secret_accessor = SecretKeyAccessor(lambda: keys_data)
    secret_accessor.get_secret.when.called_with(version=0).should.have.raised(InCryptoException)


@pytest.mark.parametrize(
    "keys_data",
    [
        {"secrets": [{"secret": "password", "version": 1}]},
        {"currentVersion": 1},
        {"currentVersion": "1", "secrets": [{"secret": "password", "version": 1}]},
        {"currentVersion": 1, "secrets": [{"secret": "password", "version": "1"}]},
        {"currentVersion": 1, "secrets": [{"secret": 1, "version": 1}]},
        {"currentVersion": 1, "secrets": []},
        {"currentVersion": 1, "secrets": [{"secret": "password", "version": 1, "isKey": "yes"}]},
        {"currentVersion": 1, "secrets": [{"secret": "password", "version": 1, "isKey": 1}]},
        {"currentVersion": 1, "secrets": [{"secret": "password", "version": 1, "isKey": True}]},
    ],
)
@pytest.mark.error_path
def test_invalid_keys_object(keys_data):
    secret_accessor = SecretKeyAccessor(lambda: keys_data)
    secret_accessor.get_secret.when.called_with().should.have.raised(InCryptoException)


@pytest.mark.parametrize(
    "keys_data",
    [
        {"currentVersion": 1, "secrets": [{"secret": "password", "version": 0}]},
        {"currentVersion": 1, "secrets": [{"secret": "password", "version": 0}, {"secret": "password", "version": 1}]},
        {"currentVersion": 0, "secrets": [{"secret": "password", "version": 1}]},
        {"currentVersion": 0, "secrets": [{"secret": "password", "version": 0}]},
    ],
)
@pytest.mark.error_path
def test_non_positive_versions_in_secrets_data(keys_data):
    secret_accessor = SecretKeyAccessor(lambda: keys_data)
    secret_accessor.get_secret.when.called_with().should.throw(InCryptoException, "ensure this value is greater than 0")
