secret_key_accessor_response_schema = {
    "type": "object",
    "required": ["currentKeyVersion", "keys"],
    "properties": {
        "currentKeyVersion": {"type": "number"},
        "keys": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "properties": {"key": {"type": "string"}, "keyVersion": {"type": "number"}},
            },
        },
    },
}
