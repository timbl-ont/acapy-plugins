package org.openwallet.acapy.oid4vc.keycloak;

import java.util.List;
import java.util.Map;
import java.util.Set;

import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MultivaluedMap;

import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.ClientAuthenticationFlowContext;
import org.keycloak.authentication.authenticators.client.AbstractClientAuthenticator;
import org.keycloak.authentication.authenticators.client.AttestationBasedClientAuthenticator;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.RefreshToken;

/**
 * Client identification hint for refresh requests from wallets without client
 * authentication.
 * <p>
 * A wallet that used the anonymous public client never learned that client's
 * id, so its refresh request has no usable {@code client_id} and Keycloak's
 * client authentication would reject it. For a {@code refresh_token} request
 * carrying one of this extension's refresh tokens issued to a <em>public</em>
 * client, this authenticator sets the {@code client_id} session attribute from
 * the token's {@code azp}; Keycloak's default {@code client-secret}
 * authenticator, which identifies public clients, falls back to that attribute
 * when the request has no {@code client_id}. It never authenticates a client
 * itself. Identifying a public client from its signed, DPoP-bound refresh token
 * is no weaker than the client sending its {@code client_id}.
 * <p>
 * Add it to the realm's client authentication flow ("clients") as ALTERNATIVE,
 * before "Client Id and Secret".
 */
public class OID4VCIRefreshClientHintAuthenticator extends AbstractClientAuthenticator {

    public static final String PROVIDER_ID = "oid4vci-refresh-client-hint";

    @Override
    public void authenticateClient(ClientAuthenticationFlowContext context) {
        MultivaluedMap<String, String> form = context.getHttpRequest().getDecodedFormParameters();
        if (form == null || !OAuth2Constants.REFRESH_TOKEN.equals(form.getFirst(OAuth2Constants.GRANT_TYPE))) {
            return;
        }
        if (form.getFirst(OAuth2Constants.CLIENT_ID) != null
                || context.getHttpRequest().getHttpHeaders().getHeaderString(HttpHeaders.AUTHORIZATION) != null
                || context.getHttpRequest().getHttpHeaders().getHeaderString(
                        AttestationBasedClientAuthenticator.OAUTH_CLIENT_ATTESTATION_HEADER) != null) {
            return;
        }
        String encoded = form.getFirst(OAuth2Constants.REFRESH_TOKEN);
        if (encoded == null) {
            return;
        }
        KeycloakSession session = context.getSession();
        RefreshToken token = session.tokens().decode(encoded, RefreshToken.class);
        if (token == null || !OID4VCIPreAuthRefreshTokenProviderFactory.PROVIDER_ID.equals(token.getProvider())
                || token.getIssuedFor() == null) {
            return;
        }
        ClientModel client = context.getRealm().getClientByClientId(token.getIssuedFor());
        if (client != null && client.isEnabled() && client.isPublicClient()) {
            session.setAttribute(OAuth2Constants.CLIENT_ID, client.getClientId());
        }
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "OID4VCI refresh client hint";
    }

    @Override
    public String getHelpText() {
        return "Identifies the public client of an OID4VCI pre-authorized code refresh token when the wallet "
                + "sends no client_id. Place before 'Client Id and Secret'.";
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of();
    }

    @Override
    public List<ProviderConfigProperty> getConfigPropertiesPerClient() {
        return List.of();
    }

    @Override
    public Map<String, Object> getAdapterConfiguration(KeycloakSession session, ClientModel client) {
        return Map.of();
    }

    @Override
    public Set<String> getProtocolAuthenticatorMethods(String loginProtocol) {
        return Set.of();
    }
}
