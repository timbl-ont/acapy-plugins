"""End-to-end test: OID4VCI pre-authorized code flow with Keycloak as the AS.

A scripted wallet drives the whole flow against the compose stack:

1. issuer controller creates a credential configuration and an offer with a tx_code;
2. wallet discovers the authorization server from the issuer metadata;
3. negative checks: token request without wallet attestation, wrong tx_code;
4. token request to Keycloak with wallet attestation (ABCA) + DPoP;
5. nonce + credential request to the issuer with the DPoP-bound token;
6. negative checks: the DPoP-bound token used as a Bearer token; the redeem
   endpoint is absent from the public port and rejects unauthenticated calls
   on the admin port.

TEST ONLY: the attester key in attester-demo-key.json is public.
"""

import base64
import hashlib
import json
import os
import sys
import time
import uuid
from urllib.parse import quote

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

ADMIN_URL = os.environ.get("ADMIN_URL", "http://localhost:3001")
CLIENT_ID = os.environ.get("CLIENT_ID", "demo-wallet")
ATTESTER_ISS = "https://attester.demo.example"
TX_CODE = "493536"
PRE_AUTH_GRANT = "urn:ietf:params:oauth:grant-type:pre-authorized_code"


# --- JOSE helpers -------------------------------------------------------------


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64int(value: int) -> str:
    return b64(value.to_bytes(32, "big"))


def unb64int(value: str) -> int:
    return int.from_bytes(
        base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)), "big"
    )


def public_jwk(key: ec.EllipticCurvePrivateKey) -> dict:
    nums = key.public_key().public_numbers()
    return {"kty": "EC", "crv": "P-256", "x": b64int(nums.x), "y": b64int(nums.y)}


def load_attester_key() -> tuple[ec.EllipticCurvePrivateKey, str]:
    with open("attester-demo-key.json") as f:
        jwk = json.load(f)["jwk"]
    public = ec.EllipticCurvePublicNumbers(
        unb64int(jwk["x"]), unb64int(jwk["y"]), ec.SECP256R1()
    )
    key = ec.EllipticCurvePrivateNumbers(unb64int(jwk["d"]), public).private_key()
    return key, jwk["kid"]


def sign(key: ec.EllipticCurvePrivateKey, header: dict, payload: dict) -> str:
    signing_input = (
        b64(json.dumps({"alg": "ES256", **header}).encode())
        + "."
        + b64(json.dumps(payload).encode())
    )
    r, s = decode_dss_signature(
        key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256()))
    )
    return signing_input + "." + b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def dpop_proof(key, htm: str, htu: str, access_token: str | None = None) -> str:
    payload = {"jti": str(uuid.uuid4()), "htm": htm, "htu": htu, "iat": int(time.time())}
    if access_token:
        payload["ath"] = b64(hashlib.sha256(access_token.encode()).digest())
    return sign(key, {"typ": "dpop+jwt", "jwk": public_jwk(key)}, payload)


class Wallet:
    """Wallet instance with an attestation from the (demo) wallet provider."""

    def __init__(self):
        self.instance_key = ec.generate_private_key(ec.SECP256R1())
        self.dpop_key = ec.generate_private_key(ec.SECP256R1())
        self.holder_key = ec.generate_private_key(ec.SECP256R1())
        attester_key, kid = load_attester_key()
        now = int(time.time())
        # Issued by the wallet provider's attester, binding the instance key.
        # Keycloak 26.8.0 takes the PoP verification algorithm from cnf.jwk's
        # "alg" and has no fallback for EC keys, so it must be present.
        self.attestation = sign(
            attester_key,
            {"typ": "oauth-client-attestation+jwt", "kid": kid},
            {
                "iss": ATTESTER_ISS,
                "sub": CLIENT_ID,
                "iat": now,
                "exp": now + 3600,
                "cnf": {"jwk": {**public_jwk(self.instance_key), "alg": "ES256"}},
            },
        )

    def attestation_headers(self, as_issuer: str) -> dict:
        pop = sign(
            self.instance_key,
            {"typ": "oauth-client-attestation-pop+jwt"},
            {
                "iss": CLIENT_ID,
                "aud": as_issuer,
                "jti": str(uuid.uuid4()),
                "iat": int(time.time()),
            },
        )
        return {
            "OAuth-Client-Attestation": self.attestation,
            "OAuth-Client-Attestation-PoP": pop,
        }


# --- Flow ------------------------------------------------------------------------


def step(title: str):
    print(f"\n=== {title}")


def expect(
    resp: requests.Response, status: int | tuple, label: str, error: str | None = None
) -> dict:
    try:
        body = resp.json()
    except ValueError:
        body = {"raw": resp.text}
    ok = resp.status_code in (status if isinstance(status, tuple) else (status,))
    if error is not None:
        ok = ok and isinstance(body, dict) and body.get("error") == error
    print(
        f"[{'ok' if ok else 'FAIL'}] {label}: HTTP {resp.status_code} {json.dumps(body)[:300]}"
    )
    if not ok:
        sys.exit(1)
    return body


def admin(method: str, path: str, **kwargs) -> dict:
    resp = requests.request(method, f"{ADMIN_URL}{path}", timeout=30, **kwargs)
    resp.raise_for_status()
    return resp.json()


def create_offer() -> tuple[dict, str]:
    step("Issuer controller: credential configuration + offer (tx_code required)")
    did = admin("POST", "/did/jwk/create", json={"key_type": "p256"})["did"]
    admin("PUT", "/oid4vci/issuer/configuration", json={})
    config_id = f"DemoCredential-{uuid.uuid4().hex[:8]}"
    supported = admin(
        "POST",
        "/oid4vci/credential-supported/create/jwt",
        json={
            "cryptographic_binding_methods_supported": ["jwk"],
            "credential_signing_alg_values_supported": ["ES256"],
            "format": "jwt_vc_json",
            "id": config_id,
            "credential_definition": {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiableCredential", "DemoCredential"],
            },
        },
    )
    exchange = admin(
        "POST",
        "/oid4vci/exchange/create",
        json={
            "supported_cred_id": supported["supported_cred_id"],
            "credential_subject": {"name": "Tom"},
            "verification_method": f"{did}#0",
            "pin": TX_CODE,
        },
    )
    offer = admin(
        "GET",
        "/oid4vci/credential-offer",
        params={"exchange_id": exchange["exchange_id"]},
    )["offer"]
    print(json.dumps(offer, indent=2))
    return offer, config_id


def main():
    offer, config_id = create_offer()
    code = offer["grants"][PRE_AUTH_GRANT]["pre-authorized_code"]
    issuer = offer["credential_issuer"]

    step("Wallet: discovery")
    meta = expect(
        requests.get(f"{issuer}/.well-known/openid-credential-issuer", timeout=10),
        200,
        "issuer metadata",
    )
    auth_server = meta["authorization_servers"][0]
    as_meta = expect(
        requests.get(f"{auth_server}/.well-known/openid-configuration", timeout=10),
        200,
        "authorization server metadata",
    )
    token_endpoint = as_meta["token_endpoint"]
    print(f"authorization server: {auth_server}\ntoken endpoint: {token_endpoint}")

    wallet = Wallet()
    form = {
        "grant_type": PRE_AUTH_GRANT,
        "pre-authorized_code": code,
        "tx_code": TX_CODE,
        "client_id": CLIENT_ID,
    }

    step("Negative: token request without wallet attestation")
    expect(
        requests.post(
            token_endpoint,
            data=form,
            headers={"DPoP": dpop_proof(wallet.dpop_key, "POST", token_endpoint)},
            timeout=10,
        ),
        (400, 401),
        "rejected (client attestation required)",
    )

    step("Negative: wrong tx_code (counts towards the lockout)")
    expect(
        requests.post(
            token_endpoint,
            data={**form, "tx_code": "000000"},
            headers={
                **wallet.attestation_headers(as_meta["issuer"]),
                "DPoP": dpop_proof(wallet.dpop_key, "POST", token_endpoint),
            },
            timeout=10,
        ),
        400,
        "rejected (invalid_grant)",
        error="invalid_grant",
    )

    step("Token request: wallet attestation + DPoP + tx_code")
    token = expect(
        requests.post(
            token_endpoint,
            data=form,
            headers={
                **wallet.attestation_headers(as_meta["issuer"]),
                "DPoP": dpop_proof(wallet.dpop_key, "POST", token_endpoint),
            },
            timeout=10,
        ),
        200,
        "access token",
    )
    access_token = token["access_token"]
    assert token["token_type"] == "DPoP", token["token_type"]
    claims = json.loads(
        base64.urlsafe_b64decode(access_token.split(".")[1] + "==").decode()
    )
    print("access token claims:", json.dumps(claims, indent=2))

    step("Nonce + credential request (DPoP-bound token)")
    nonce = expect(requests.post(meta["nonce_endpoint"], timeout=10), 200, "nonce")
    proof = sign(
        wallet.holder_key,
        {"typ": "openid4vci-proof+jwt", "jwk": public_jwk(wallet.holder_key)},
        {"aud": issuer, "iat": int(time.time()), "nonce": nonce["c_nonce"]},
    )
    cred_endpoint = meta["credential_endpoint"]
    credential = expect(
        requests.post(
            cred_endpoint,
            json={"credential_configuration_id": config_id, "proofs": {"jwt": [proof]}},
            headers={
                "Authorization": f"DPoP {access_token}",
                "DPoP": dpop_proof(wallet.dpop_key, "POST", cred_endpoint, access_token),
            },
            timeout=30,
        ),
        200,
        "credential",
    )
    print("credential:", credential["credentials"][0]["credential"][:120], "...")

    step("Negative: DPoP-bound token presented as Bearer")
    expect(
        requests.post(
            cred_endpoint,
            json={"credential_configuration_id": config_id},
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10,
        ),
        401,
        "rejected",
    )

    step("Negative: redeem endpoint (trusted back channel)")
    expect(
        requests.post(f"{issuer}/oid4vci/pre-auth/redeem", data={}, timeout=10),
        404,
        "not served on the public OID4VCI port",
    )
    expect(
        requests.post(
            f"{ADMIN_URL}/oid4vci/pre-auth/redeem",
            data={"pre_authorized_code": code, "client_id": "anyone"},
            timeout=10,
        ),
        401,
        "admin port: rejected without Keycloak's client authentication",
        error="invalid_client",
    )
    print("\nDone.")
    print(
        f"Offer link: openid-credential-offer://?credential_offer={quote(json.dumps(offer))}"
    )


if __name__ == "__main__":
    main()
