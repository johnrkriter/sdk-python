import os
from incountry import Storage
from pytest_testrail.plugin import pytestrail
from incountry import SecretKeyAccessor
import uuid

API_KEY = os.environ.get("INC_API_KEY")
ENVIRONMENT_ID = os.environ.get("INC_ENVIRONMENT_ID")
ENDPOINT = os.environ.get("INC_ENDPOINT")
SECRETS_DATA = {
    "secrets": [{"secret": "supersecret", "version": 2}],
    "currentVersion": 2,
}


@pytestrail.case("C149")
def test_e2e():
    client = Storage(
        api_key=API_KEY,
        environment_id=ENVIRONMENT_ID,
        endpoint=ENDPOINT,
        encrypt=True,
        secret_key_accessor=SecretKeyAccessor(lambda: SECRETS_DATA),
        debug=True,
    )

    # This pattern will be useful for parameterized tests when we are ready for them
    test_case = {
        "country": "us",
        "key": uuid.uuid4().hex,
        "body": "test",
    }

    write_response = client.write(country=test_case["country"], key=test_case["key"], body=test_case["body"],)

    read_response = client.read(country=test_case["country"], key=test_case["key"])

    assert read_response is not None
    assert read_response["body"] == test_case["body"]
    assert read_response["key"] == test_case["key"]
    assert read_response["version"] == 2

    delete_response = client.delete(country=test_case["country"], key=test_case["key"])
