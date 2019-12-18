import pytest
import sure


from incountry import SecretKeyAccessor, SecretKeyAccessorException


@pytest.mark.parametrize("password", ["password"])
@pytest.mark.happy_path
def test_get_secret(password):
    secret_accessor = SecretKeyAccessor(lambda: password)
    assert secret_accessor.get_secret() == password


@pytest.mark.error_path
def test_non_callable_accessor_function():
    SecretKeyAccessor.when.called_with("password").should.have.raised(SecretKeyAccessorException)
