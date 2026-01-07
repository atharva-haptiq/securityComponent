package com.haptiq.securityComponent.service.strategy;

import com.haptiq.securityComponent.Strategy;
import com.haptiq.securityComponent.model.TokenValidationResult;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.net.URL;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Strategy 2: Remote JWKS Validation (Current Approach)
 * - Fetches public keys from Keycloak JWKS endpoint
 * - Caches keys with TTL
 * - Validates token using fetched keys
 */

@Service
public class RemoteJWKSValidationService {

    private static final Logger LOGGER = LoggerFactory.getLogger(RemoteJWKSValidationService.class);

    @Value("${token.validation.keycloak.jwks-uri}")
    private String jwksUri;

    @Value("${token.validation.keycloak.issuer-uri}")
    private String issuerUri;

    @Value("${token.validation.remote-jwks.cache-duration-minutes}")
    private int cacheDurationMinutes;

    private final ConcurrentHashMap<String, CachedJWKSet> jwksCache = new ConcurrentHashMap<>();

    public TokenValidationResult validate(String token) {
        LOGGER.debug("Validating token using Remote JWKS from URI: {}", jwksUri);

        try {
            SignedJWT signedJWT = SignedJWT.parse(token);

            String keyID = signedJWT.getHeader().getKeyID();
            if (keyID == null || keyID.isEmpty()) {
                LOGGER.error("Key ID is missing in JWT header.");
                return new TokenValidationResult(false, "Key ID is missing in JWT",
                    Strategy.REMOTE_JWKS);
            }
            LOGGER.debug("Extracted Key ID from token: {}", keyID);

            JWKSet jwkSet = fetchRemoteKeySet();
            if (jwkSet == null) {
                return new TokenValidationResult(false, "Failed to fetch JWKS",
                    Strategy.REMOTE_JWKS);
            }

            JWK jwk = jwkSet.getKeyByKeyId(keyID);
            if (jwk == null) {
                LOGGER.debug("Key not found in cache for Key ID: {}. Refreshing JWKS.", keyID);
                jwksCache.remove(jwksUri);
                jwkSet = fetchRemoteKeySet();
                if (jwkSet == null) {
                    LOGGER.error("Failed to refresh JWKS from URI: {}", jwksUri);
                    return new TokenValidationResult(false, "Failed to fetch JWKS after refresh",
                        Strategy.REMOTE_JWKS);
                }
                jwk = jwkSet.getKeyByKeyId(keyID);
                if (jwk == null) {
                    LOGGER.error("Key with ID: {} not found in JWKS after refresh.", keyID);
                    return new TokenValidationResult(false, "Key not found in JWKS",
                        Strategy.REMOTE_JWKS);
                }
            }

            RSAKey rsaKey = (RSAKey) jwk;
            JWSVerifier jwsVerifier = new RSASSAVerifier(rsaKey.toRSAPublicKey());

            if (!signedJWT.verify(jwsVerifier)) {
                return new TokenValidationResult(false, "JWT signature verification failed",
                    Strategy.REMOTE_JWKS);
            }

            JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();

            Date expirationTime = jwtClaimsSet.getExpirationTime();
            if (expirationTime == null || expirationTime.before(new Date())) {
                return new TokenValidationResult(false, "JWT token is expired",
                    Strategy.REMOTE_JWKS);
            }

            if (!issuerUri.equals(jwtClaimsSet.getIssuer())) {
                return new TokenValidationResult(false, "Invalid issuer", Strategy.REMOTE_JWKS);
            }
            TokenValidationResult validationResult = new TokenValidationResult(true,
                "Token is valid", Strategy.REMOTE_JWKS);
            validationResult.setUserName(jwtClaimsSet.getStringClaim("preferred_username"));
            validationResult.setEmail(jwtClaimsSet.getStringClaim("email"));
            validationResult.setExpiresAt(expirationTime.toInstant());

            Map<String, Object> claims = jwtClaimsSet.getClaims();
            validationResult.setClaims(claims);

            LOGGER.debug("Token successfully validated using refreshed JWKS.");
            return validationResult;

        } catch (Exception exception) {
            LOGGER.error("Error validating JWT token: {}", exception.getMessage());
            return new TokenValidationResult(false, "Invalid JWT format", Strategy.REMOTE_JWKS);
        }
    }

    private JWKSet fetchRemoteKeySet() {
        CachedJWKSet cachedJWKSet = jwksCache.get(jwksUri);
        Instant now = Instant.now();

        if (cachedJWKSet != null
            && Duration.between(cachedJWKSet.timeStamp, now).toMinutes() < cacheDurationMinutes) {
            LOGGER.debug("Using cached JWKS for URI: {}", jwksUri);
            return cachedJWKSet.jwkSet;
        }

        try {
            LOGGER.debug("Fetching new JWKS from URI: {}", jwksUri);
            JWKSet jwkSet = JWKSet.load(new URL(jwksUri));
            jwksCache.put(jwksUri, new CachedJWKSet(jwkSet, now));
            LOGGER.info("Successfully fetched and cached JWKS with {} keys.",
                jwkSet.getKeys().size());
            return jwkSet;
        } catch (Exception exception) {
            LOGGER.error("Failed to fetch JWKS from URI: {} Error: {}", jwksUri,
                exception.getMessage());
            return null;
        }

    }

    private static class CachedJWKSet {

        public final JWKSet jwkSet;
        public final Instant timeStamp;

        public CachedJWKSet(JWKSet jwkSet, Instant timeStamp) {
            this.jwkSet = jwkSet;
            this.timeStamp = timeStamp;
        }
    }
}
