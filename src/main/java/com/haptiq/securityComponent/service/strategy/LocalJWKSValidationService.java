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
import jakarta.annotation.PostConstruct;
import java.io.InputStream;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Service;

/**
 * Strategy 1: Local JWKS Validation
 * - Loads public keys from local file
 * - Validates token offline (no network call)
 * - Fastest validation, suitable for high-throughput scenarios
 */
@Service
public class LocalJWKSValidationService {

    private static final Logger LOG = LoggerFactory.getLogger(LocalJWKSValidationService.class);

    @Value("${token.validation.local-jwks.file-path}")
    private String JWKSFilePath;

    @Value("${token.validation.keycloak.issuer-uri}")
    private String issuerUri;

    private JWKSet localJwkSet;
    private final ResourceLoader resourceLoader;

    public LocalJWKSValidationService(ResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
        LOG.info("LocalJWKSValidationService initialized with JWKS file path: {}", JWKSFilePath);
    }

    @PostConstruct
    public void loadLocalJWKS(){
        try{
            LOG.info("Loading local JWKS from : {}",JWKSFilePath);
            Resource resource = resourceLoader.getResource(JWKSFilePath);
            try(InputStream inputStream = resource.getInputStream()){
                localJwkSet = JWKSet.load(inputStream);
                LOG.info("Successfully loaded local JWKS with {} keys.", localJwkSet.getKeys().size());
            }
            catch (Exception exception){
                LOG.error("Failed to load local JWKS from file: {}", exception.getMessage());
            }
        }
        catch (Exception exception){
            LOG.error("Error accessing JWKS file resource: {}", exception.getMessage());
        }
    }

    public TokenValidationResult validate(String token){
        TokenValidationResult result = new TokenValidationResult();
        LOG.debug("Preparing TokenValidationResult with local JWKS URI: {}", issuerUri);
        if (localJwkSet == null){
            LOG.error("Local JWKS is not loaded. Cannot prepare TokenValidationResult.");
            return new TokenValidationResult(false, "Local JWKS not loaded", Strategy.LOCAL_JWKS);
        }
        try{

            //parse our jwt token
            SignedJWT signedJWT = SignedJWT.parse(token);

            // Get key ID from token header
            String keyId = signedJWT.getHeader().getKeyID();

            // Find matching key in local JWKS
            JWK jwk = localJwkSet.getKeyByKeyId(keyId);
            if (jwk == null){
                LOG.error("No matching JWK found for key ID: {}", keyId);
                return new TokenValidationResult(false,
                    "Key with id " + keyId + " not found in local JWKS", Strategy.LOCAL_JWKS);
            }
            // Convert to RSA key
            RSAKey rsaKey = (RSAKey) jwk;

            // Verify signature
            JWSVerifier jwsVerifier = new RSASSAVerifier(rsaKey.toRSAPublicKey());
            if (!signedJWT.verify(jwsVerifier)){
                LOG.error("JWT signature verification failed for key ID: {}", keyId);
                return new TokenValidationResult(false, "JWT signature verification failed", Strategy.LOCAL_JWKS);
            }

            // Get claims
            JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();

            // Validate expiry
            Date expirationTime = jwtClaimsSet.getExpirationTime();
            if(expirationTime == null || expirationTime.before(new Date())){
                LOG.error("JWT token is expired. Expiration time: {}", expirationTime);
                return new TokenValidationResult(false, "JWT token is expired", Strategy.LOCAL_JWKS);
            }

            //most important part validate issuer
            String issuer = jwtClaimsSet.getIssuer();
            if(!issuerUri.equals(issuer)){
                LOG.error("JWT issuer mismatch. Expected: {}, Found: {}", issuerUri, issuer);
                return new TokenValidationResult(false, "JWT issuer mismatch", Strategy.LOCAL_JWKS);
            }
            result.setValid(true);
            result.setUserName(jwtClaimsSet.getStringClaim("preferred_username"));
            result.setEmail(jwtClaimsSet.getStringClaim("email"));
            result.setExpiresAt(expirationTime.toInstant());
            result.setStrategy(Strategy.LOCAL_JWKS);

            Map<String, Object> claims = new HashMap<>(jwtClaimsSet.getClaims());
            result.setClaims(claims);

            LOG.debug("JWT token successfully validated for user: {}", result.getUserName());
            return result;
        }
        catch (Exception exception){
            LOG.error("Error parsing JWT token: {}", exception.getMessage());
            return new TokenValidationResult(false, "Invalid JWT token", Strategy.LOCAL_JWKS);
        }
    }
}
