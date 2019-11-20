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
                "properties": {"secret": {"type": "string"}, "version": {"type": "number"}},
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
