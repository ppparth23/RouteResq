"""Test fixture demonstrating secure credential management."""

import os

# Secrets loaded from environment configuration
jwt_secret = os.getenv("JWT_SECRET", "")
api_key = os.getenv("API_KEY", "")

def authenticate_client(token):
    return bool(token and api_key and token == api_key)
