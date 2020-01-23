secret_key_accessor_response_schema = {
    "type": "object",
    "required": ["currentVersion", "secrets"],
    "properties": {
        "currentVersion": {"type": "number"},
        "secrets": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "properties": {
                    "secret": {"type": "string"},
                    "version": {"type": "number"},
                    "isKey": {"type": "boolean"},
                },
            },
        },
    },
}

batch_records_schema = {
    "type": "array",
    "minItems": 1,
    "items": {
        "type": "object",
        "required": ["key"],
        "properties": {
            "key": {"type": "string"},
            "key2": {"type": "string"},
            "key3": {"type": "string"},
            "profile_key": {"type": "string"},
            "body": {"type": "string"},
            "range_key": {"type": "number"},
        },
    },
}

record_schema = {
    "type": "object",
    "required": ["key"],
    "properties": {
        "key": {"type": "string"},
        "body": {"type": "string"},
        "country": {"type": ["string", "null"]},
        "version": {"type": ["number", "null"]},
        "profile_key": {"type": ["string", "null"]},
        "range_key": {"type": ["number", "null"]},
        "key2": {"type": ["string", "null"]},
        "key3": {"type": ["string", "null"]},
    },
}

find_response_schema = {
    "type": "object",
    "properties": {
        "meta": {
            "type": "object",
            "required": ["count", "limit", "offset", "total"],
            "properties": {
                "count": {"type": "number"},
                "limit": {"type": "number"},
                "offset": {"type": "number"},
                "total": {"type": "number"},
            },
        },
        "data": {"type": "array", "items": record_schema},
    },
}

write_response_schema = {"type": "string", "enum": ["OK"]}
