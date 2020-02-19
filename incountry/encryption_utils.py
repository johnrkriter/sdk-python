import json
from .incountry_crypto import InCrypto


def validate_crypto(crypto):
    if not isinstance(crypto, InCrypto):
        raise Exception(f"'crypto' argument should be an instance of InCrypto. Got {type(crypto)}")


def validate_is_string(value, arg_name):
    if not isinstance(value, str):
        raise Exception(f"'{arg_name}' argument should be of type string. Got {type(value)}")


def is_json(data):
    try:
        json.loads(data)
    except ValueError:
        return False
    return True


def hash_custom_key(crypto, value, salt):
    validate_crypto(crypto)
    validate_is_string(value, "value")
    validate_is_string(salt, "salt")
    return crypto.hash(value + ":" + salt)


def encrypt_record(crypto, record, salt):
    validate_crypto(crypto)
    validate_is_string(salt, "salt")
    res = dict(record)
    body = {"meta": {}, "payload": None}
    for k in ["key", "key2", "key3", "profile_key"]:
        if res.get(k):
            body["meta"][k] = res.get(k)
            res[k] = hash_custom_key(crypto, res[k], salt)
    if res.get("body"):
        body["payload"] = res.get("body")

    [enc_data, key_version] = crypto.encrypt(json.dumps(body))
    res["body"] = enc_data
    res["version"] = key_version
    return res


def decrypt_record(crypto, record):
    validate_crypto(crypto)
    res = dict(record)
    if res.get("body"):
        res["body"] = crypto.decrypt(res["body"], res["version"])
        if is_json(res["body"]):
            body = json.loads(res["body"])
            if body.get("payload"):
                res["body"] = body.get("payload")
            else:
                del res["body"]
            for k in ["key", "key2", "key3", "profile_key"]:
                if record.get(k) and body["meta"].get(k):
                    res[k] = body["meta"][k]
    return res
