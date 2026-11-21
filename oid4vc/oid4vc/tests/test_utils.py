"""Tests for oid4vc utils."""

import pytest

from oid4vc.utils import get_auth_header, get_tenant_subpath, oid4vp_response_uri


def test_get_tenant_subpath(profile):
    profile.context.settings.set_value("multitenant.enabled", True)
    assert get_tenant_subpath(profile) == "/tenants/538451fa-11ab-41de-b6e3-7ae3df7356d6"


def test_oid4vp_response_uri(monkeypatch, profile):
    monkeypatch.delenv("OID4VCI_ENDPOINT", raising=False)
    monkeypatch.delenv("OID4VP_ENDPOINT", raising=False)
    assert (
        oid4vp_response_uri(profile, "pres-1")
        == "http://localhost:8020/oid4vp/response/pres-1"
    )


def test_oid4vp_response_uri_prefers_oid4vp_endpoint_and_tenant(monkeypatch, profile):
    monkeypatch.delenv("OID4VCI_ENDPOINT", raising=False)
    monkeypatch.setenv("OID4VP_ENDPOINT", "https://vp.example.com")
    profile.context.settings.set_value("multitenant.enabled", True)
    assert oid4vp_response_uri(profile, "pres-1") == (
        "https://vp.example.com/tenant/538451fa-11ab-41de-b6e3-7ae3df7356d6"
        "/oid4vp/response/pres-1"
    )


@pytest.mark.asyncio
async def test_get_auth_header_client_secret_basic(monkeypatch, profile):
    auth_server = {
        "auth_type": "client_secret_basic",
        "client_credentials": {
            "client_id": "client_id",
            "client_secret": "client_secret",
        },
    }
    header = await get_auth_header(profile, auth_server, "issuer", "audience")
    assert header.startswith("Basic ")


@pytest.mark.asyncio
async def test_get_auth_header_missing_client(monkeypatch, profile):
    auth_server = {"auth_type": "client_secret_basic"}
    with pytest.raises(ValueError):
        await get_auth_header(profile, auth_server, "issuer", "audience")
