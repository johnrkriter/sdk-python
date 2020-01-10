import os
from incountry import Storage
from pytest_testrail.plugin import pytestrail
from incountry import SecretKeyAccessor
import uuid


API_KEY = os.environ.get("INT_INC_API_KEY")
ENVIRONMENT_ID = os.environ.get("INT_INC_ENVIRONMENT_ID")
ENDPOINT = os.environ.get("INT_INC_ENDPOINT")
COUNTRY = os.environ.get("INT_INC_COUNTRY")
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
        "country": COUNTRY,
        "key": uuid.uuid4().hex,
        "body": "test",
    }

    client.write(
        country=test_case["country"], key=test_case["key"], body=test_case["body"],
    )

    read_response = client.read(country=test_case["country"], key=test_case["key"])

    assert read_response is not None
    assert read_response["record"]["body"] == test_case["body"]
    assert read_response["record"]["key"] == test_case["key"]
    assert read_response["record"]["version"] == SECRETS_DATA["currentVersion"]

    client.delete(country=test_case["country"], key=test_case["key"])
