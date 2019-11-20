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
