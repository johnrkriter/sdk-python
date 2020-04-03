import pytest
import sure  # noqa: F401


from incountry import SecretKeyAccessor, StorageClientError


INVALID_SECRETS_DATA = [
    [],
    {},
    (),
    False,
    True,
    0,
    1,
    {"secrets": [{"secret": "password", "version": 1}]},
    {"currentVersion": 1},
    {"currentVersion": "1", "secrets": [{"secret": "password", "version": 1}]},
    {"currentVersion": 1, "secrets": [{"secret": "password", "version": "1"}]},
    {"currentVersion": 1, "secrets": [{"secret": 1, "version": 1}]},
    {"currentVersion": 1, "secrets": []},
    {"currentVersion": 1, "secrets": [{"secret": "password", "version": 1, "isKey": "yes"}]},
    {"currentVersion": 1, "secrets": [{"secret": "password", "version": 1, "isKey": 1}]},
    {"currentVersion": 1, "secrets": [{"secret": "password", "version": 0}]},
    {"currentVersion": 1, "secrets": [{"secret": "password", "version": -1}, {"secret": "password", "version": 1}]},
    {"currentVersion": 0, "secrets": [{"secret": "password", "version": 1}]},
]

INVALID_SECRETS_DATA_WITH_SHORT_KEY = [
    *INVALID_SECRETS_DATA,
    {"currentVersion": 1, "secrets": [{"secret": "password", "version": 1, "isKey": True}]},
]


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
        ({"currentVersion": 0, "secrets": [{"secret": "password0", "version": 0}]}, 0, "password0", False),
        (
            {
                "currentVersion": 1,
                "secrets": [{"secret": "password1", "version": 1}, {"secret": "password2", "version": 2}],
            },
            1,
            "password1",
            False,
        ),
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


# @pytest.mark.parametrize(
#     "keys_data, proper_version, proper_key, proper_is_key",
#     [
#         (
#             {
#                 "currentVersion": 2,
#                 "secrets": [{"secret": "password1", "version": 1}, {"secret": "1234", "version": 2, "isKey": True}],
#             },
#             2,
#             "1234",
#             True,
#         ),
#     ],
# )
# @pytest.mark.happy_path
# def test_get_secret_ignoring_length_validation(keys_data, proper_version, proper_key, proper_is_key):
#     secret_accessor = SecretKeyAccessor(lambda: keys_data)
#     [secret, secret_version, is_key] = secret_accessor.get_secret(ignore_length_validation=True)
#     assert secret_version == proper_version
#     assert secret == proper_key
#     assert is_key == proper_is_key


# @pytest.mark.error_path
# def test_non_callable_accessor_function():
#     SecretKeyAccessor.when.called_with("password").should.have.raised(StorageClientError)


# @pytest.mark.error_path
# def test_incorrect_version_requested():
#     secret_accessor = SecretKeyAccessor(lambda: "some password")
#     secret_accessor.get_secret.when.called_with("non int").should.have.raised(StorageClientError)


# @pytest.mark.parametrize("keys_data", [{"currentVersion": 1, "secrets": [{"secret": "password", "version": 1}]}])
# @pytest.mark.error_path
# def test_non_existing_version_requested(keys_data):
#     secret_accessor = SecretKeyAccessor(lambda: keys_data)
#     secret_accessor.get_secret.when.called_with(version=0).should.have.raised(StorageClientError)


# @pytest.mark.parametrize(
#     "keys_data", INVALID_SECRETS_DATA,
# )
# @pytest.mark.error_path
# def test_invalid_keys_object(keys_data):
#     SecretKeyAccessor.when.called_with(lambda: keys_data).should.have.raised(StorageClientError)


# @pytest.mark.parametrize(
#     "keys_data", INVALID_SECRETS_DATA_WITH_SHORT_KEY,
# )
# @pytest.mark.error_path
# def test_invalid_keys_object_during_get_secret(keys_data):
#     global i
#     i = 0

#     def accessor_function():
#         global i
#         i = i + 1
#         if i <= 1:
#             return "password"
#         return keys_data

#     secret_accessor = SecretKeyAccessor(accessor_function)
#     secret_accessor.get_secret.when.called_with().should.have.raised(StorageClientError)


# @pytest.mark.parametrize(
#     "keys_data", INVALID_SECRETS_DATA,
# )
# @pytest.mark.error_path
# def test_invalid_keys_object_during_get_secrets_raw(keys_data):
#     global i
#     i = 0

#     def accessor_function():
#         global i
#         i = i + 1
#         if i <= 1:
#             return "password"
#         return keys_data

#     secret_accessor = SecretKeyAccessor(accessor_function)
#     secret_accessor.get_secrets_raw.when.called_with().should.have.raised(StorageClientError)


# @pytest.mark.error_path
# def test_errorful_accessor_function():
#     def accessor_function():
#         raise Exception("HTTP 500")

#     SecretKeyAccessor.when.called_with(accessor_function).should.have.raised(
#         StorageClientError, "failed to retrieve secret keys data"
#     )


# @pytest.mark.error_path
# def test_errorful_accessor_function_after_successful_validation():
#     global i
#     i = 0

#     def accessor_function():
#         global i
#         i = i + 1
#         if i <= 1:
#             return "password"
#         raise Exception("HTTP 500")

#     secret_accessor = SecretKeyAccessor(accessor_function)
#     secret_accessor.get_secrets_raw.when.called_with().should.have.raised(
#         StorageClientError, "Failed to retrieve secret keys data"
#     )
