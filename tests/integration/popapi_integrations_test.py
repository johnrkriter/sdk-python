from incountry import Storage
from pytest_testrail.plugin import pytestrail
from incountry import SecretKeyAccessor


@pytestrail.case('С149')
def test_e2e():
    client = Storage(
        api_key="fjoxhg.7ea9257f8fe54899b8e8136c62fd02a3",
        environment_id="b6517bec-2a52-4730-aa50-a90e2272bb2f",
        endpoint='https://us.staging.incountry.io/',
        encrypt=True,
        secret_key_accessor=SecretKeyAccessor(lambda: 'supersecret'),
        debug=True
    )

    # This pattern will be useful for parameterized tests when we are ready for them
    test_case = {
        'country': 'us',
        'key': 'record0',
        'body': 'test',
    }

    write_response = client.write(
        country=test_case['country'],
        key=test_case['key'],
        body=test_case['body'],
    )

    read_response = client.read(
        country=test_case['country'],
        key=test_case['key']
    )

    assert read_response is not None
    assert read_response['body'] == test_case['body']
    assert read_response['key'] == test_case['key']
    assert read_response['version'] == 1

    delete_response = client.delete(
        country=test_case['country'],
        key=test_case['key']
    )
