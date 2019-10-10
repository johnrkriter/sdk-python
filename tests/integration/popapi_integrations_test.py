import pytest
from incountry import Storage

def test_e2e():
    client = Storage(encrypt=True, secret_key='supersecret', debug=True)

    # This pattern will be useful for parameterized tests when we are ready for them
    test_case = {
        "country": "us",
        "key": "record0",
        "body": "test"
    }

    write_response = client.write(
        country=test_case["country"],
        key=test_case["key"],
        body=test_case["body"]
    )

    read_response = client.read(
        country=test_case["country"],
        key=test_case["key"]
    )

    assert read_response is not None
    assert read_response['body'] == test_case["body"]
    assert read_response["key"] == test_case["key"]
    assert read_response["version"] == 1

    delete_response = client.delete(
        country=test_case["country"],
        key=test_case["key"]
    )