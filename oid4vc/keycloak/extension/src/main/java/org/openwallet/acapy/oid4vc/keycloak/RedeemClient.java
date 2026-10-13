package org.openwallet.acapy.oid4vc.keycloak;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.keycloak.TokenCategory;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.TokenManager;
import org.keycloak.services.Urls;
import org.keycloak.util.JsonSerialization;

import org.jboss.logging.Logger;

/**
 * Back-channel call to the plugin's redeem endpoint.
 * <p>
 * The request is authenticated with a short-lived JWT signed by the realm's
 * active access-token key ({@code typ: oid4vci-redeem+jwt}); the plugin
 * verifies it against the realm JWKS it already uses for access tokens.
 */
final class RedeemClient {

    static final String ASSERTION_TYPE = "oid4vci-redeem+jwt";
    private static final int ASSERTION_TTL_SECONDS = 60;

    private static final Logger LOGGER = Logger.getLogger(RedeemClient.class);
    private static final HttpClient HTTP = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

    /** Successful redemption. */
    record Redemption(String refreshId, List<String> credentialConfigurationIds, Integer expiresIn) {
    }

    /** Redemption refused by the plugin (OAuth error code) or failed. */
    static final class RedeemException extends Exception {
        final String error;
        final boolean unavailable;

        RedeemException(String error, String message, boolean unavailable) {
            super(message);
            this.error = error;
            this.unavailable = unavailable;
        }
    }

    private RedeemClient() {
    }

    static Redemption redeem(KeycloakSession session, RealmModel realm, Oid4vciPreAuthConfig config,
                             String code, String txCode, String clientId) throws RedeemException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("pre_authorized_code", code);
        if (txCode != null) {
            body.put("tx_code", txCode);
        }
        if (clientId != null) {
            body.put("client_id", clientId);
        }

        HttpResponse<String> response;
        try {
            HttpRequest request = HttpRequest.newBuilder(config.redeemUrl)
                    .timeout(Duration.ofMillis(config.redeemTimeoutMs))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .header("Authorization", "Bearer " + assertion(session, realm, config))
                    .POST(HttpRequest.BodyPublishers.ofString(JsonSerialization.writeValueAsString(body)))
                    .build();
            response = HTTP.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RedeemException("server_error", "redeem call interrupted", true);
        } catch (IOException | RuntimeException e) {
            LOGGER.warnf(e, "Pre-authorized code redeem call to %s failed", config.redeemUrl);
            throw new RedeemException("server_error", "redeem call failed", true);
        }

        Map<?, ?> json;
        try {
            json = JsonSerialization.readValue(response.body(), Map.class);
        } catch (IOException e) {
            json = Map.of();
        }

        if (response.statusCode() == 200) {
            Object refreshId = json.get("refresh_id");
            Object ids = json.get("credential_configuration_ids");
            if (!(refreshId instanceof String) || !(ids instanceof List<?> list) || list.isEmpty()) {
                throw new RedeemException("server_error", "malformed redeem response", true);
            }
            Object expiresIn = json.get("expires_in");
            return new Redemption((String) refreshId,
                    list.stream().map(String::valueOf).toList(),
                    expiresIn instanceof Number n ? n.intValue() : null);
        }
        if (response.statusCode() == 400) {
            Object error = json.get("error");
            String code400 = "invalid_request".equals(error) ? "invalid_request" : "invalid_grant";
            throw new RedeemException(code400, String.valueOf(json.get("error_description")), false);
        }
        LOGGER.warnf("Pre-authorized code redeem call returned HTTP %d", response.statusCode());
        throw new RedeemException("server_error", "redeem call returned " + response.statusCode(), true);
    }

    private static String assertion(KeycloakSession session, RealmModel realm, Oid4vciPreAuthConfig config) {
        String issuer = Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName());
        long now = Time.currentTime();
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", issuer);
        claims.put("aud", config.credentialIssuer);
        claims.put("iat", now);
        claims.put("exp", now + ASSERTION_TTL_SECONDS);
        claims.put("jti", UUID.randomUUID().toString());

        TokenManager tokens = session.tokens();
        String algorithm = tokens.signatureAlgorithm(TokenCategory.ACCESS);
        SignatureSignerContext signer;
        try {
            signer = session.getProvider(SignatureProvider.class, algorithm).signer();
        } catch (Exception e) {
            throw new IllegalStateException("No active realm signing key for " + algorithm, e);
        }
        return new JWSBuilder().type(ASSERTION_TYPE).jsonContent(claims).sign(signer);
    }
}
