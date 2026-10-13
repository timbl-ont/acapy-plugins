package org.openwallet.acapy.oid4vc.keycloak;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

import jakarta.ws.rs.core.Response;

import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.authentication.authenticators.client.AttestationBasedClientAuthenticator;
import org.keycloak.common.util.Time;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.protocol.oidc.grants.OAuth2GrantTypeBase;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.dpop.DPoP;
import org.keycloak.services.CorsErrorResponseException;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.managers.UserSessionManager;
import org.keycloak.services.util.DPoPUtil;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

import org.jboss.logging.Logger;

/**
 * OID4VCI pre-authorized code grant backed by the ACA-Py OID4VC plugin.
 * <p>
 * The plugin owns the pre-authorized code, the tx_code and the exchange. This
 * grant does what the plugin should not have to: authenticate the wallet
 * (attestation-based client authentication) and bind the token to a DPoP key.
 * It then redeems the code at the plugin and issues a short-lived, DPoP-bound
 * access token for a generic holder user, carrying the exchange's refresh_id.
 * <p>
 * Order matters: the client and the DPoP proof are checked before the code is
 * redeemed, so an unauthenticated request cannot burn a code or a tx_code
 * attempt.
 */
public class Oid4vciPreAuthGrantType extends OAuth2GrantTypeBase {

    static final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
    static final String CODE_PARAM = "pre-authorized_code";
    static final String TX_CODE_PARAM = "tx_code";
    static final String CREDENTIAL_CONFIGURATION_IDS_CLAIM = "credential_configuration_ids";
    static final String AUTH_METHOD = "oid4vci-pre-authorized-code";
    static final String INVALID_DPOP_PROOF = "invalid_dpop_proof";

    private static final Logger LOGGER = Logger.getLogger(Oid4vciPreAuthGrantType.class);

    @Override
    public Response process(Context context) {
        setContext(context);
        Oid4vciPreAuthConfig config = Oid4vciPreAuthConfig.of(realm);
        if (!config.isComplete()) {
            LOGGER.errorf("Realm '%s' is missing %s / %s", realm.getName(),
                    Oid4vciPreAuthConfig.REDEEM_URL, Oid4vciPreAuthConfig.CREDENTIAL_ISSUER);
            event.error(Errors.INVALID_REQUEST);
            throw error("server_error", "pre-authorized code grant is not configured",
                    Response.Status.INTERNAL_SERVER_ERROR);
        }

        String code = formParams.getFirst(CODE_PARAM);
        if (code == null || code.isBlank()) {
            event.detail(Details.REASON, "missing " + CODE_PARAM).error(Errors.INVALID_CODE);
            throw error(OAuthErrorException.INVALID_REQUEST, "Missing parameter: " + CODE_PARAM,
                    Response.Status.BAD_REQUEST);
        }
        String txCode = formParams.getFirst(TX_CODE_PARAM);

        // 1. Client authentication (TokenEndpoint skips checkClient() for this grant type).
        authenticateClient(config);

        // 2. DPoP: TokenEndpoint already validated a proof if one was sent.
        DPoP dpop = session.getAttribute(DPoPUtil.DPOP_SESSION_ATTRIBUTE, DPoP.class);
        if (config.requireDpop && dpop == null) {
            event.detail(Details.REASON, "DPoP proof required").error(Errors.INVALID_DPOP_PROOF);
            throw error(INVALID_DPOP_PROOF, "DPoP proof is required", Response.Status.BAD_REQUEST);
        }

        // authorization_details in the token request is ignored: the credential
        // configuration comes from the offer the plugin created.

        // 3. Redeem the code at the plugin.
        RedeemClient.Redemption redemption;
        try {
            redemption = RedeemClient.redeem(session, realm, config, code, txCode, client.getClientId());
        } catch (RedeemClient.RedeemException e) {
            event.detail(Details.REASON, e.getMessage()).error(Errors.INVALID_CODE);
            if (e.unavailable) {
                throw error("temporarily_unavailable", "Credential issuer unavailable",
                        Response.Status.SERVICE_UNAVAILABLE);
            }
            throw error(e.error, OAuthErrorException.INVALID_REQUEST.equals(e.error)
                    ? "Invalid token request" : "Invalid pre-authorized code or tx_code",
                    Response.Status.BAD_REQUEST);
        }

        // 4. Generic holder user and a transient session: Keycloak does not know the holder.
        UserModel holder = session.users().getUserByUsername(realm, config.holderUsername);
        if (holder == null || !holder.isEnabled()) {
            LOGGER.errorf("Realm '%s' has no enabled holder user '%s'", realm.getName(), config.holderUsername);
            event.error(Errors.USER_NOT_FOUND);
            throw error("server_error", "pre-authorized code grant is not configured",
                    Response.Status.INTERNAL_SERVER_ERROR);
        }
        event.user(holder).detail(Details.USERNAME, holder.getUsername());

        String scope = getRequestedScopes();
        RootAuthenticationSessionModel rootAuthSession =
                new AuthenticationSessionManager(session).createAuthenticationSession(realm, false);
        AuthenticationSessionModel authSession = rootAuthSession.createAuthenticationSession(client);
        authSession.setAuthenticatedUser(holder);
        authSession.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        authSession.setClientNote(OIDCLoginProtocol.ISSUER,
                Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName()));
        authSession.setClientNote(OIDCLoginProtocol.SCOPE_PARAM, scope);

        UserSessionModel userSession = new UserSessionManager(session).createUserSession(
                authSession.getParentSession().getId(), realm, holder, holder.getUsername(),
                clientConnection.getRemoteHost(), AUTH_METHOD, false, null, null,
                UserSessionModel.SessionPersistenceState.TRANSIENT);
        event.session(userSession);

        AuthenticationManager.setClientScopesInSession(session, authSession);
        ClientSessionContext clientSessionCtx =
                TokenManager.attachAuthenticationSession(session, userSession, authSession);
        if (clientAuthAttributes != null) {
            updateUserSessionFromClientAuth(userSession);
        }

        // 5./6. Short-lived access token, no refresh token. The DPoP protocol
        // mapper binds cnf.jkt because a validated proof is in the session.
        TokenManager.AccessTokenResponseBuilder responseBuilder =
                createTokenResponseBuilder(holder, userSession, clientSessionCtx, scope, null);
        AccessToken token = responseBuilder.getAccessToken();
        token.setOtherClaims(config.refreshIdClaim, redemption.refreshId());
        token.setOtherClaims(CREDENTIAL_CONFIGURATION_IDS_CLAIM, redemption.credentialConfigurationIds());
        token.addAudience(config.credentialIssuer);
        if (redemption.expiresIn() != null && redemption.expiresIn() > 0) {
            long cap = (long) Time.currentTime() + redemption.expiresIn();
            if (token.getExp() == null || token.getExp() > cap) {
                token.exp(cap);
            }
        }
        return createTokenResponse(responseBuilder, clientSessionCtx, false);
    }

    private void authenticateClient(Oid4vciPreAuthConfig config) {
        boolean clientIdentified = formParams.getFirst(OAuth2Constants.CLIENT_ID) != null
                || headers.getHeaderString(AttestationBasedClientAuthenticator.OAUTH_CLIENT_ATTESTATION_HEADER) != null
                || headers.getHeaderString("Authorization") != null;

        if (clientIdentified) {
            checkClient(); // runs the realm client flow, including the ABCA authenticator
        } else if (!config.requireClientAttestation && config.anonymousClientId != null) {
            client = realm.getClientByClientId(config.anonymousClientId);
            if (client == null || !client.isEnabled() || !client.isPublicClient()) {
                event.error(Errors.CLIENT_NOT_FOUND);
                throw error(OAuthErrorException.INVALID_CLIENT, "Anonymous client is not available",
                        Response.Status.UNAUTHORIZED);
            }
            clientConfig = OIDCAdvancedConfigWrapper.fromClientModel(client);
            clientAuthAttributes = Map.of();
        } else {
            event.error(Errors.INVALID_CLIENT);
            throw error(OAuthErrorException.INVALID_CLIENT,
                    config.requireClientAttestation ? "Client attestation is required" : "client_id is required",
                    Response.Status.UNAUTHORIZED);
        }

        session.getContext().setClient(client);
        context.setClient(client);
        event.client(client);

        if (config.requireClientAttestation) {
            AttestationBasedClientAuthenticator.ABCAResult abca = session.getAttribute(
                    AttestationBasedClientAuthenticator.ABCAResult.ABCA_RESULT,
                    AttestationBasedClientAuthenticator.ABCAResult.class);
            ClientModel attested = abca == null ? null : abca.getAttestedClient();
            if (attested == null || !attested.getId().equals(client.getId())) {
                event.detail(Details.REASON, "client attestation required").error(Errors.INVALID_CLIENT);
                throw error(OAuthErrorException.INVALID_CLIENT, "Client attestation is required",
                        Response.Status.UNAUTHORIZED);
            }
        }
    }

    private CorsErrorResponseException error(String error, String description, Response.Status status) {
        return new CorsErrorResponseException(cors, error, description, status);
    }

    @Override
    protected boolean useRefreshToken() {
        return false;
    }

    @Override
    public EventType getEventType() {
        return EventType.CLIENT_LOGIN;
    }

    @Override
    public Set<String> getTokenParameterNames() {
        return Collections.emptySet();
    }
}
