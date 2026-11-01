"""Test fixture demonstrating hardcoded secrets."""

# Hardcoded sensitive tokens
jwt_secret = "secret_key_super_confidential_9999"
api_key = "AIzaSyD-HARDCODED-GEMINI-TOKEN-12345"

def authenticate_client(token):
    return token == api_key
