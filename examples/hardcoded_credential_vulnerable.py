"""VULNEX AI Demo Fixture: Intentionally Vulnerable Hardcoded Credential.

CWE-798: Use of Hard-coded Credentials
Risk: Hardcoded tokens and secrets committed to repositories can be extracted by unauthorized parties.
NOTE: Uses a purely synthetic mock token for demonstration purposes only.
"""


class PaymentGatewayClient:
    """Mock payment gateway client using an API credential."""

    # VULNERABILITY (CWE-798): Hardcoded synthetic API key embedded in source code
    api_key = "synthetic_demo_api_key_vulnex_hackathon_998877"

    def __init__(self, endpoint_url: str = "https://mock.gateway.local/v1"):
        self.endpoint_url = endpoint_url

    def get_auth_headers(self) -> dict:
        """Construct authorization headers for outgoing service requests."""
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
