package org.openwallet.acapy.oid4vc.keycloak;

import java.net.URI;

import org.keycloak.models.RealmModel;

/**
 * Per-realm configuration, read from realm attributes so each realm (one per
 * issuer tenant) can point at its own plugin instance.
 */
final class Oid4vciPreAuthConfig {

    /** Plugin redeem endpoint, e.g. http://issuer:8022/oid4vci/pre-auth/redeem (required). */
    static final String REDEEM_URL = "oid4vci.redeem.url";
    /** Credential Issuer Identifier of the plugin (required). Used as audience. */
    static final String CREDENTIAL_ISSUER = "oid4vci.credential.issuer";
    /** Require attestation-based client authentication (default true). */
    static final String REQUIRE_CLIENT_ATTESTATION = "oid4vci.require.client.attestation";
    /** Require a DPoP proof and issue DPoP-bound tokens (default true). */
    static final String REQUIRE_DPOP = "oid4vci.require.dpop";
    /**
     * Client used when the wallet sends no client_id. Only honoured when client
     * attestation is not required; unset means anonymous requests are rejected.
     */
    static final String ANONYMOUS_CLIENT_ID = "oid4vci.anonymous.client.id";
    /** Username of the generic, credential-less holder user (default oid4vci-holder). */
    static final String HOLDER_USERNAME = "oid4vci.holder.username";
    /** Access token claim carrying the plugin exchange refresh_id (default refresh_id). */
    static final String REFRESH_ID_CLAIM = "oid4vci.refresh.id.claim";
    /** Timeout for the redeem call in milliseconds (default 5000). */
    static final String REDEEM_TIMEOUT_MS = "oid4vci.redeem.timeout.ms";

    final URI redeemUrl;
    final String credentialIssuer;
    final boolean requireClientAttestation;
    final boolean requireDpop;
    final String anonymousClientId;
    final String holderUsername;
    final String refreshIdClaim;
    final int redeemTimeoutMs;

    private Oid4vciPreAuthConfig(RealmModel realm) {
        String redeem = realm.getAttribute(REDEEM_URL);
        this.redeemUrl = redeem == null || redeem.isBlank() ? null : URI.create(redeem.trim());
        this.credentialIssuer = trimToNull(realm.getAttribute(CREDENTIAL_ISSUER));
        this.requireClientAttestation = bool(realm.getAttribute(REQUIRE_CLIENT_ATTESTATION), true);
        this.requireDpop = bool(realm.getAttribute(REQUIRE_DPOP), true);
        this.anonymousClientId = trimToNull(realm.getAttribute(ANONYMOUS_CLIENT_ID));
        this.holderUsername = orDefault(realm.getAttribute(HOLDER_USERNAME), "oid4vci-holder");
        this.refreshIdClaim = orDefault(realm.getAttribute(REFRESH_ID_CLAIM), "refresh_id");
        this.redeemTimeoutMs = intOr(realm.getAttribute(REDEEM_TIMEOUT_MS), 5000);
    }

    static Oid4vciPreAuthConfig of(RealmModel realm) {
        return new Oid4vciPreAuthConfig(realm);
    }

    boolean isComplete() {
        return redeemUrl != null && credentialIssuer != null;
    }

    private static String trimToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    private static String orDefault(String value, String fallback) {
        String trimmed = trimToNull(value);
        return trimmed == null ? fallback : trimmed;
    }

    private static boolean bool(String value, boolean fallback) {
        String trimmed = trimToNull(value);
        return trimmed == null ? fallback : Boolean.parseBoolean(trimmed);
    }

    private static int intOr(String value, int fallback) {
        try {
            String trimmed = trimToNull(value);
            return trimmed == null ? fallback : Integer.parseInt(trimmed);
        } catch (NumberFormatException e) {
            return fallback;
        }
    }
}
