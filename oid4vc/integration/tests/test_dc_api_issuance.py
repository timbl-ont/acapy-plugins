"""Integration tests for OpenID4VCI over the W3C Digital Credentials API.

The test plays the wallet: it takes the Credential Offer that a page would pass
to ``navigator.credentials.create()`` (protocol ``openid4vci-v1``), checks that
the metadata embedded by value matches what the issuer serves under
``/.well-known/``, and completes issuance with the offer's pre-authorized code.
"""

import pytest
from acapy_controller.controller import Controller
from aiohttp import ClientSession

from oid4vci_client.client import OpenID4VCIClient

EMBEDDED = ("credential_issuer_metadata", "authorization_server_metadata")


async def fetch_json(url: str) -> dict:
    async with ClientSession() as session:
        async with session.get(url) as resp:
            assert resp.status == 200, await resp.text()
            return await resp.json()


@pytest.mark.asyncio
async def test_dc_api_credential_offer(
    controller: Controller,
    test_client: OpenID4VCIClient,
    issuer_did: str,
    supported_cred_id: str,
):
    exchange = await controller.post(
        "/oid4vci/exchange/create",
        json={
            "supported_cred_id": supported_cred_id,
            "credential_subject": {"name": "alice"},
            "verification_method": issuer_did + "#0",
        },
    )
    offer = await controller.get(
        "/oid4vci/dc-api/credential-offer",
        params={"exchange_id": exchange["exchange_id"]},
    )

    assert offer["protocol"] == "openid4vci-v1"
    data = offer["data"]
    issuer = data["credential_issuer"]

    # Metadata by value equals metadata by reference.
    assert data["credential_issuer_metadata"] == await fetch_json(
        f"{issuer}/.well-known/openid-credential-issuer"
    )
    assert data["authorization_server_metadata"] == await fetch_json(
        f"{issuer}/.well-known/oauth-authorization-server"
    )

    # Complete issuance with the offer's pre-authorized code.
    did = test_client.generate_did("ed25519")
    plain_offer = {k: v for k, v in data.items() if k not in EMBEDDED}
    response = await test_client.receive_offer({"offer": plain_offer}, did)
    assert response.get("credentials") or response.get("credential")

    record = await controller.get(f"/oid4vci/exchange/records/{exchange['exchange_id']}")
    assert record["state"] == "issued"
