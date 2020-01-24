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

custom_encryption_configurations_schema = {
    "type": "array",
    "minItems": 1,
    "items": {
        "type": "object",
        "required": ["encrypt", "decrypt", "version", "isCurrent"],
        "properties": {
            "encrypt": {"type": "function"},
            "decrypt": {"type": "function"},
            "version": {"type": "string"},
            "isCurrent": {"type": "boolean"},
        },
    },
}
