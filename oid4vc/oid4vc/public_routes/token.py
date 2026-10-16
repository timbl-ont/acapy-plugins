"""Token endpoint for OID4VCI."""

import json
import time
from secrets import token_urlsafe
from typing import Any, Dict
from urllib.parse import urlparse

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.core.profile import Profile
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.wallet.base import WalletError
from acapy_agent.wallet.error import WalletNotFoundError
from acapy_agent.wallet.jwt import b64_to_dict
from acapy_agent.wallet.util import b64_to_bytes
from aiohttp import web
from aiohttp_apispec import docs, form_schema
from aries_askar import Key
from marshmallow import fields, pre_load

from oid4vc.did_utils import retrieve_or_create_did_jwk
from oid4vc.jwt import (
    JWTVerifyResult,  # noqa: F401 — re-exported by public_routes
    jwt_sign,
    key_from_x5c,
    key_material_for_kid,
)

from ..auth_providers import (
    AccessTokenResult,
    InvalidTokenError,
    resolve_auth_provider,
)
from ..config import Config
from ..dpop import DPOP_HEADER, DPoPError, verify_dpop_proof
from ..models.nonce import Nonce
from ..pop_result import PopResult
from ..pre_auth import PreAuthCodeError, redeem_pre_auth_code
from ..utils import public_request_url
from .constants import (
    EXPIRES_IN,
    LOGGER,
    NONCE_BYTES,
    PRE_AUTHORIZED_CODE_GRANT_TYPE,
)


class GetTokenSchema(OpenAPISchema):
    """Schema for the token endpoint.

    Accept both 'pre-authorized_code' (OID4VCI v1.0) and legacy
    'pre_authorized_code' (underscore) for compatibility by normalizing input.
    """

    grant_type = fields.Str(required=True, metadata={"description": "", "example": ""})

    pre_authorized_code = fields.Str(
        data_key="pre-authorized_code",
        required=True,
        metadata={"description": "", "example": ""},
    )
    user_pin = fields.Str(required=False)

    @pre_load
    def normalize_fields(self, data, **_kwargs):
        """Normalize legacy field names to OID4VCI v1.0 keys.

        Accept 'pre_authorized_code' by mapping it to 'pre-authorized_code'.
        """
        # webargs may pass a MultiDictProxy; make a writable copy first
        try:
            mutable = dict(data)
        except (TypeError, ValueError):
            mutable = data
        # Map legacy underscore field to the hyphenated v1.0 key if needed
        if "pre_authorized_code" in mutable and "pre-authorized_code" not in mutable:
            mutable["pre-authorized_code"] = mutable.get("pre_authorized_code")
        return mutable


def _token_error(error: str, description: str, status: int = 400) -> web.Response:
    return web.json_response(
        {"error": error, "error_description": description}, status=status
    )


@docs(tags=["oid4vci"], summary="Get credential issuance token")
@form_schema(GetTokenSchema())
async def token(request: web.Request):
    """Token endpoint to exchange pre-authorized codes for access tokens.

    Served only by the built-in authorization server. A ``DPoP`` proof, when
    sent, is verified and the issued token is bound to its key (RFC 9449).

    OID4VCI v1.0: This step MUST NOT require DID or verification method.
    """
    context: AdminRequestContext = request["context"]
    async with context.profile.session() as session:
        provider, _ = await resolve_auth_provider(session, context.profile)
    if not provider.serves_token_endpoint:
        # The wallet should never reach this endpoint when an external auth server
        # is configured — it should obtain a token directly from the auth server's
        # token_endpoint advertised in the AS well-known metadata.
        return _token_error(
            "invalid_request",
            "Token endpoint not available: use the authorization server",
        )
    form = await request.post()

    if (form.get("grant_type")) != PRE_AUTHORIZED_CODE_GRANT_TYPE:
        return _token_error("unsupported_grant_type", "grant_type not supported")

    config = Config.from_settings(context.settings)

    # Verify DPoP before redeeming so an invalid request cannot burn the code.
    jkt = None
    dpop_proof = request.headers.get(DPOP_HEADER)
    if dpop_proof:
        try:
            jkt = verify_dpop_proof(
                dpop_proof, htm="POST", htu=public_request_url(config, request)
            )
        except DPoPError as err:
            return _token_error("invalid_dpop_proof", err.description)

    # Accept both hyphenated and underscored keys, and legacy user_pin.
    pre_authorized_code = form.get("pre-authorized_code") or form.get(
        "pre_authorized_code"
    )
    tx_code = form.get("tx_code") or form.get("user_pin")
    try:
        record = await redeem_pre_auth_code(
            context.profile,
            pre_authorized_code if isinstance(pre_authorized_code, str) else None,
            tx_code if isinstance(tx_code, str) else None,
        )
    except PreAuthCodeError as err:
        return _token_error(err.error, err.description)

    payload: Dict[str, Any] = {
        "sub": record.refresh_id,
        "exp": int(time.time()) + EXPIRES_IN,
    }
    if jkt:
        payload["cnf"] = {"jkt": jkt}

    # v1 compliance: do not require DID/verification method at token step.
    # Sign with a default did:jwk under this wallet to produce a JWT access token.
    async with context.profile.session() as session:
        try:
            jwk_info = await retrieve_or_create_did_jwk(session)
            vm = f"{jwk_info.did}#0"
            token_jwt = await jwt_sign(
                context.profile,
                headers={"kid": vm, "typ": "JWT"},
                payload=payload,
                verification_method=vm,
            )
        except (WalletNotFoundError, WalletError, ValueError) as err:
            return _token_error(
                "server_error", f"Unable to sign access token: {str(err)}", 500
            )

        record.token = token_jwt
        await record.save(
            session,
            reason="Created new token",
        )

    # Nonce handling per OID4VCI 1.0:
    #   - enable_nonce_endpoint=True: do NOT generate or return a c_nonce here.
    #     The wallet obtains a fresh nonce per credential request from POST
    #     /nonce (spec §7), which is redeemed during PoP validation.
    #   - enable_nonce_endpoint=False: no Nonce Endpoint is published, so we
    #     fall back to the legacy flow — return c_nonce in the token response
    #     and store it on the exchange record for later comparison.
    response: Dict[str, Any] = {
        "access_token": record.token,
        "token_type": "DPoP" if jkt else "Bearer",
        "expires_in": EXPIRES_IN,
    }
    if not config.enable_nonce_endpoint:
        c_nonce_value = token_urlsafe(NONCE_BYTES)
        async with context.profile.session() as session:
            record.nonce = c_nonce_value
            await record.save(session, reason="Stored c_nonce for PoP validation")
        response["c_nonce"] = c_nonce_value
        response["c_nonce_expires_in"] = EXPIRES_IN

    return web.json_response(
        response, headers={"Cache-Control": "no-store", "Pragma": "no-cache"}
    )


def _unauthorized(error: str, description: str, scheme: str = "Bearer"):
    return web.HTTPUnauthorized(
        text=json.dumps({"error": error, "error_description": description}),
        headers={
            "Content-Type": "application/json",
            "WWW-Authenticate": f'{scheme} error="{error}"',
        },
    )


async def check_token(
    context: AdminRequestContext,
    bearer: str | None = None,
    *,
    dpop_proof: str | None = None,
    htu: str | None = None,
    htm: str = "POST",
) -> AccessTokenResult:
    """Validate an access token presented to the issuer (resource server).

    The configured authorization server provider validates the token itself.
    DPoP (RFC 9449 §7) is then enforced here, independent of the provider:

    - a token bound with ``cnf.jkt`` must use the ``DPoP`` scheme and come
      with a valid proof (``htm``/``htu``/``ath``, key matching ``cnf.jkt``);
    - providers that require DPoP reject unbound tokens.

    Unbound tokens presented with the ``DPoP`` scheme are accepted for
    compatibility with wallets that always use it.
    """
    if not bearer:
        raise web.HTTPUnauthorized()
    try:
        scheme, cred = bearer.split(" ", 1)
    except ValueError:
        raise web.HTTPUnauthorized() from None
    scheme = scheme.lower()
    if scheme not in ("bearer", "dpop"):
        raise web.HTTPUnauthorized()

    profile = context.profile
    async with profile.session() as session:
        provider, ctx = await resolve_auth_provider(session, profile)

    try:
        result = await provider.validate_access_token(ctx, cred)
    except InvalidTokenError as err:
        raise _unauthorized("invalid_token", err.description) from err

    cnf = result.payload.get("cnf")
    jkt = cnf.get("jkt") if isinstance(cnf, dict) else None
    if jkt:
        if scheme != "dpop":
            raise _unauthorized(
                "invalid_token", "DPoP-bound token must use the DPoP scheme", "DPoP"
            )
        if htu is None:
            htu = f"{ctx.issuer_url}/credential"
        try:
            verify_dpop_proof(
                dpop_proof, htm=htm, htu=htu, access_token=cred, expected_jkt=jkt
            )
        except DPoPError as err:
            raise _unauthorized(err.error, err.description, "DPoP") from err
    elif provider.require_dpop(ctx):
        raise _unauthorized("invalid_token", "DPoP-bound access token required", "DPoP")

    return AccessTokenResult(
        result.headers,
        result.payload,
        True,
        exchange_key=provider.exchange_key(ctx, result.payload),
    )


async def handle_proof_of_posession(
    profile: Profile, proof: Dict[str, Any], c_nonce: str | None = None
):
    """Validate the proof of possession JWT in a Credential Request.

    Nonce validation strategy depends on ``config.enable_nonce_endpoint``:
      - True: nonce is redeemed via the local DB (``Nonce.redeem_by_value``).
        The ``c_nonce`` argument is ignored — when the Nonce Endpoint is
        published, the issuer is the sole authority on nonce lifecycle, and
        any c_nonce that may have been carried in an external AS's token
        response is irrelevant.
      - False: nonce is validated by direct comparison against ``c_nonce``,
        which the caller obtains from the token introspect payload (external
        AS) or the exchange record (built-in token endpoint).
    """
    encoded_headers, encoded_payload, encoded_signature = proof["jwt"].split(".", 3)
    headers = b64_to_dict(encoded_headers)

    # OID4VCI 1.0 requires typ="openid4vci-proof+jwt"
    # But accept common draft spec values for backward compatibility
    typ = headers.get("typ")
    valid_typ_values = ["openid4vci-proof+jwt", "JWT", "jwt", "openid4vci-jwt"]
    if typ and typ not in valid_typ_values:
        LOGGER.warning("Proof JWT has unexpected typ header: %s", typ)
        raise web.HTTPBadRequest(
            text=json.dumps(
                {
                    "error": "invalid_proof",
                    "error_description": f"unsupported typ: {typ}",
                }
            ),
            content_type="application/json",
        )

    if "jwk" in headers:
        # Prefer inline JWK over kid-based DID resolution (OID4VCI spec §7.2.1).
        # Wallets such as walt.id send both kid and jwk in the proof header;
        # resolving the kid as a DID URL fails when the key is not registered in
        # a resolvable DID document, causing a spurious "invalid kid in proof".
        key = Key.from_jwk(headers["jwk"])
    elif "kid" in headers:
        try:
            key = await key_material_for_kid(profile, headers["kid"])
        except ValueError as exc:
            raise web.HTTPBadRequest(
                text=json.dumps(
                    {
                        "error": "invalid_proof",
                        "error_description": "invalid kid in proof",
                    }
                ),
                content_type="application/json",
            ) from exc
    elif "x5c" in headers:
        # OID4VCI 1.0: wallet may use x5c (certificate-based) key binding.
        # Extract the public key from the leaf cert for signature verification.
        try:
            key = key_from_x5c(headers["x5c"])
        except Exception as exc:
            LOGGER.debug("Failed to extract key from x5c cert chain: %s", exc)
            raise web.HTTPBadRequest(
                text=json.dumps(
                    {
                        "error": "invalid_proof",
                        "error_description": "invalid x5c certificate in proof header",
                    }
                ),
                content_type="application/json",
            ) from exc
    else:
        # No key material in the header. Some draft-era wallets (e.g. walt.id)
        # omit jwk/kid/x5c from the proof header and instead put the DID in the
        # payload `iss` claim. Decode the payload first and attempt resolution.
        payload_for_iss = b64_to_dict(encoded_payload)
        iss = payload_for_iss.get("iss")
        if iss:
            # key_material_for_kid expects a DID URL (with fragment), not a bare
            # DID.  For did:jwk and did:key the first verification method is #0.
            kid_url = iss if "#" in iss else f"{iss}#0"
            try:
                key = await key_material_for_kid(profile, kid_url)
                LOGGER.debug("Resolved proof key from payload iss: %s", iss)
            except (ValueError, Exception) as exc:
                LOGGER.debug("Could not resolve key from iss '%s': %s", iss, exc)
                raise web.HTTPBadRequest(
                    text=json.dumps(
                        {
                            "error": "invalid_proof",
                            "error_description": "no key material in proof header and"
                            " iss could not be resolved",
                        }
                    ),
                    content_type="application/json",
                ) from exc
        else:
            raise web.HTTPBadRequest(
                text=json.dumps(
                    {
                        "error": "invalid_proof",
                        "error_description": "no key material in proof header",
                    }
                ),
                content_type="application/json",
            )

    payload = b64_to_dict(encoded_payload)

    # OID4VCI 1.0 § 7.2.2: the proof JWT MUST contain an `aud` claim equal to
    # the Credential Issuer Identifier (the issuer's base URL).  Omitting this
    # check allows proof replay across issuers.
    aud = payload.get("aud")
    if aud is not None:
        issuer_endpoint = Config.from_settings(profile.settings).endpoint
        # aud may be a string or a list of strings (per RFC 7519 § 4.1.3)
        aud_values = [aud] if isinstance(aud, str) else list(aud)

        def _strip_default_port(url: str) -> str:
            """Remove explicit default ports (https:443, http:80) for comparison."""
            try:
                p = urlparse(url)
                if (p.scheme == "https" and p.port == 443) or (
                    p.scheme == "http" and p.port == 80
                ):
                    netloc = p.hostname or ""
                    return p._replace(netloc=netloc).geturl()
            except Exception:
                pass
            return url

        norm_endpoint = _strip_default_port(issuer_endpoint) if issuer_endpoint else ""
        if issuer_endpoint and not any(
            _strip_default_port(av) == norm_endpoint
            or _strip_default_port(av).startswith(norm_endpoint + "/tenant/")
            for av in aud_values
        ):
            raise web.HTTPBadRequest(
                text=json.dumps(
                    {
                        "error": "invalid_proof",
                        "error_description": (
                            f"proof JWT aud '{aud}' does not match "
                            f"issuer endpoint '{issuer_endpoint}'"
                        ),
                    }
                ),
                content_type="application/json",
            )

    # OID4VCI 1.0 final spec uses "nonce"; older draft wallets may use "c_nonce".
    nonce = payload.get("nonce") or payload.get("c_nonce")

    config = Config.from_settings(profile.settings)
    if config.enable_nonce_endpoint:
        # The /nonce endpoint is published — nonces are managed locally in the DB.
        # Use DB-based redemption regardless of any c_nonce from the access token.
        async with profile.session() as session:
            redeemed = await Nonce.redeem_by_value(session, nonce)
        if not redeemed:
            raise web.HTTPBadRequest(
                text=json.dumps(
                    {
                        "error": "invalid_nonce",
                        "error_description": "invalid or already-used nonce",
                    }
                ),
                content_type="application/json",
            )
    else:
        # No local nonce endpoint — rely on c_nonce from the access token.
        if not c_nonce:
            raise web.HTTPBadRequest(
                text=json.dumps(
                    {
                        "error": "invalid_nonce",
                        "error_description": "no c_nonce available to verify proof",
                    }
                ),
                content_type="application/json",
            )
        if c_nonce != nonce:
            raise web.HTTPBadRequest(
                text=json.dumps(
                    {
                        "error": "invalid_nonce",
                        "error_description": "nonce mismatch",
                    }
                ),
                content_type="application/json",
            )

    decoded_signature = b64_to_bytes(encoded_signature, urlsafe=True)
    verified = key.verify_signature(
        f"{encoded_headers}.{encoded_payload}".encode(),
        decoded_signature,
        sig_type=headers.get("alg", ""),
    )

    # If the wallet sent a kid-based proof (no jwk in header), derive the public
    # JWK from the resolved key so credential processors that need the raw JWK
    # (e.g. mso_mdoc for holder key binding in DeviceKey) can access it.
    holder_jwk = headers.get("jwk")
    if holder_jwk is None and (
        "kid" in headers or not any(k in headers for k in ("jwk", "kid", "x5c"))
    ):
        try:
            holder_jwk = json.loads(key.get_jwk_public())
        except Exception:
            LOGGER.debug("Could not derive holder JWK from resolved key")

    return PopResult(
        headers,
        payload,
        verified,
        holder_kid=headers.get("kid"),
        holder_jwk=holder_jwk,
        holder_x5c=headers.get("x5c"),
    )
