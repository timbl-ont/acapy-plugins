package org.openwallet.acapy.oid4vc.keycloak;

import java.io.IOException;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import org.keycloak.TokenCategory;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.Urls;
import org.keycloak.util.JsonSerialization;
import org.keycloak.vault.VaultStringSecret;

import org.jboss.logging.Logger;

/**
 * Back-channel call to the plugin's redeem endpoint on its admin API.
 * <p>
 * Keycloak is an OAuth client of the plugin and authenticates with the
 * method configured in {@code oid4vci.redeem.client.auth}:
 * <ul>
 *   <li>{@code private_key_jwt} (default, RFC 7523): a client assertion signed
 *       with the realm's active access-token key; the plugin verifies it against
 *       the realm JWKS, so there is no shared secret.</li>
 *   <li>{@code client_secret_jwt}: the same assertion, HMAC-signed with the
 *       configured secret.</li>
 *   <li>{@code client_secret_post}: client_id + client_secret form parameters.</li>
 * </ul>
 * Credentials are sent in the form body: on the ACA-Py admin port the
 * {@code Authorization} header is reserved for ACA-Py tenant tokens.
 */
final class RedeemClient {

    static final String JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    static final String PRIVATE_KEY_JWT = "private_key_jwt";
    static final String CLIENT_SECRET_JWT = "client_secret_jwt";
    static final String CLIENT_SECRET_POST = "client_secret_post";
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
                             String code, String txCode, String walletClientId) throws RedeemException {
        Map<String, String> form = new LinkedHashMap<>();
        form.put("pre_authorized_code", code);
        if (txCode != null) {
            form.put("tx_code", txCode);
        }
        if (walletClientId != null) {
            form.put("wallet_client_id", walletClientId);
        }

        HttpResponse<String> response;
        try {
            addClientAuthentication(session, realm, config, form);
            HttpRequest request = HttpRequest.newBuilder(config.redeemUrl)
                    .timeout(Duration.ofMillis(config.redeemTimeoutMs))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .header("Accept", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(encode(form)))
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
        if (response.statusCode() == 401) {
            LOGGER.errorf("The plugin rejected Keycloak's client authentication for %s; check "
                    + "oid4vci.redeem.client.* and the tenant's redeem_client settings", config.redeemUrl);
        } else {
            LOGGER.warnf("Pre-authorized code redeem call returned HTTP %d", response.statusCode());
        }
        throw new RedeemException("server_error", "redeem call returned " + response.statusCode(), true);
    }

    private static void addClientAuthentication(KeycloakSession session, RealmModel realm,
                                                Oid4vciPreAuthConfig config, Map<String, String> form) {
        String clientId = config.redeemClientId != null ? config.redeemClientId
                : Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName());
        switch (config.redeemClientAuth) {
            case PRIVATE_KEY_JWT -> {
                form.put("client_assertion_type", JWT_BEARER);
                form.put("client_assertion", new JWSBuilder().type("JWT")
                        .jsonContent(assertionClaims(clientId, config)).sign(realmSigner(session)));
            }
            case CLIENT_SECRET_JWT -> {
                form.put("client_assertion_type", JWT_BEARER);
                form.put("client_assertion", new JWSBuilder().type("JWT")
                        .jsonContent(assertionClaims(clientId, config))
                        .hmac256(secret(session, config).getBytes(StandardCharsets.UTF_8)));
            }
            case CLIENT_SECRET_POST -> {
                form.put("client_id", clientId);
                form.put("client_secret", secret(session, config));
            }
            default -> throw new IllegalStateException(
                    "Unsupported " + Oid4vciPreAuthConfig.REDEEM_CLIENT_AUTH + ": " + config.redeemClientAuth);
        }
    }

    private static Map<String, Object> assertionClaims(String clientId, Oid4vciPreAuthConfig config) {
        long now = Time.currentTime();
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", clientId);
        claims.put("sub", clientId);
        claims.put("aud", config.redeemUrl.toString());
        claims.put("iat", now);
        claims.put("exp", now + ASSERTION_TTL_SECONDS);
        claims.put("jti", UUID.randomUUID().toString());
        return claims;
    }

    private static SignatureSignerContext realmSigner(KeycloakSession session) {
        String algorithm = session.tokens().signatureAlgorithm(TokenCategory.ACCESS);
        try {
            return session.getProvider(SignatureProvider.class, algorithm).signer();
        } catch (Exception e) {
            throw new IllegalStateException("No active realm signing key for " + algorithm, e);
        }
    }

    /** The configured secret; a ${vault.key} reference is resolved through the Keycloak vault. */
    private static String secret(KeycloakSession session, Oid4vciPreAuthConfig config) {
        if (config.redeemClientSecret == null) {
            throw new IllegalStateException(Oid4vciPreAuthConfig.REDEEM_CLIENT_SECRET + " is not set");
        }
        try (VaultStringSecret secret = session.vault().getStringSecret(config.redeemClientSecret)) {
            return secret.get().orElseThrow(() -> new IllegalStateException(
                    Oid4vciPreAuthConfig.REDEEM_CLIENT_SECRET + " could not be resolved"));
        }
    }

    private static String encode(Map<String, String> form) {
        return form.entrySet().stream()
                .map(e -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "="
                        + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                .collect(Collectors.joining("&"));
    }
}
