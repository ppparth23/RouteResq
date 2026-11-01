"""Test fixture demonstrating Insecure Deserialization via pickle."""

import pickle

def unpack_user_session(serialized_data):
    # Insecure deserialization of arbitrary object graph
    return pickle.loads(serialized_data)
