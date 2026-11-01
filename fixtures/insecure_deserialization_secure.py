"""Test fixture demonstrating secure structured deserialization via JSON."""

import json

def unpack_user_session(serialized_data):
    # Safe JSON deserialization
    return json.loads(serialized_data.decode("utf-8") if isinstance(serialized_data, bytes) else serialized_data)
