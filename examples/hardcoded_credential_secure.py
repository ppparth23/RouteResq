"""VULNEX AI Demo Fixture: Remediated Secure Credential Handling Counterpart.

CWE-798 Remediation: Externalized Credential from Runtime Environment
Defense: Secrets are loaded from environment variables or a secret vault at runtime,
keeping source code clean of static secrets.
"""

import os


class PaymentGatewayClient:
    """Mock payment gateway client using an externalized API credential."""

    def __init__(self, endpoint_url: str = "https://mock.gateway.local/v1"):
        self.endpoint_url = endpoint_url
        # REMEDIATION: Retrieve token from environment variable with fallback guard
        self.api_key = os.getenv("PAYMENT_GATEWAY_API_KEY", "")

    def get_auth_headers(self) -> dict:
        """Construct authorization headers for outgoing service requests."""
        if not self.api_key:
            raise ValueError("PAYMENT_GATEWAY_API_KEY environment variable is not configured")
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
