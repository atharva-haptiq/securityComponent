package com.haptiq.securityComponent.service.strategy;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.haptiq.securityComponent.Strategy;
import com.haptiq.securityComponent.model.TokenValidationResult;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

/**
 * Strategy 3: Token Introspection
 * - Sends token to Keycloak's introspection endpoint
 * - Keycloak validates and returns active/inactive
 * - Most secure (knows about revoked tokens)
 * - Slowest (network call on every request)
 */
@Service
public class IntrospectionValidationService {

    private static final Logger LOGGER = LoggerFactory.getLogger(IntrospectionValidationService.class);

    @Value("${token.validation.keycloak.introspection-uri}")
    private String introspectionUri;

    @Value("${token.validation.keycloak.client-id}")
    private String clientId;

    @Value("${token.validation.keycloak.client-secret}")
    private String clientSecret;

    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper objectMapper = new ObjectMapper();

    public TokenValidationResult validate(String token) {
        LOGGER.debug("Validating token using INTROSPECTION strategy");
        LOGGER.debug("Introspection URI: {}", introspectionUri);
        LOGGER.debug("Client ID: {}", clientId);
        LOGGER.debug("Client Secret configured: {}", (clientSecret != null && !clientSecret.isEmpty()));

        try {
            // Prepare headers
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            // Add Basic Auth if client secret is provided
            if (clientSecret != null && !clientSecret.isEmpty()) {
                String auth = clientId + ":" + clientSecret;
                String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes());
                headers.set("Authorization", "Basic " + encodedAuth);
                LOGGER.debug("Using Basic Auth with client credentials");
            } else {
                LOGGER.warn("⚠️ No client secret configured - introspection may fail");
            }

            // Prepare body
            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("token", token);
            body.add("client_id", clientId);

            if (clientSecret != null && !clientSecret.isEmpty()) {
                body.add("client_secret", clientSecret);
            }

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

            // Call Keycloak introspection endpoint
            LOGGER.debug("Sending introspection request to: {}", introspectionUri);
            ResponseEntity<String> response = restTemplate.exchange(
                introspectionUri,
                HttpMethod.POST,
                request,
                String.class
            );

            // Log response status and body
            LOGGER.debug("Introspection response status: {}", response.getStatusCode());
            LOGGER.debug("Introspection response body: {}", response.getBody());

            // Parse response
            Map<String, Object> introspectionResponse = objectMapper.readValue(
                response.getBody(),
                new TypeReference<Map<String, Object>>() {}
            );

            // Check if token is active
            boolean active = (Boolean) introspectionResponse.getOrDefault("active", false);

            if (!active) {
                LOGGER.warn("Token is not active according to Keycloak");
                return new TokenValidationResult(false, "Token is not active", Strategy.INTROSPECTION);
            }

            // Build successful result
            TokenValidationResult result = new TokenValidationResult(true, "Token is valid", Strategy.INTROSPECTION);
            result.setUserName((String) introspectionResponse.get("preferred_username"));
            result.setEmail((String) introspectionResponse.getOrDefault("email", ""));

            // Parse expiry
            Object exp = introspectionResponse.get("exp");
            if (exp instanceof Number) {
                result.setExpiresAt(Instant.ofEpochSecond(((Number) exp).longValue()));
            }

            result.setClaims(introspectionResponse);

            LOGGER.info("✅ Token validated successfully using INTROSPECTION");
            return result;

        } catch (HttpClientErrorException e) {
             LOGGER.error("❌ HTTP error from Keycloak introspection endpoint:");
            LOGGER.error("   Status: {}", e.getStatusCode());
            LOGGER.error("   Response: {}", e.getResponseBodyAsString());

            if (e.getStatusCode() == HttpStatus.UNAUTHORIZED) {
                return new TokenValidationResult(false,
                    "Unauthorized - Check client credentials", Strategy.INTROSPECTION);
            }

            return new TokenValidationResult(false,
                "Introspection failed: " + e.getStatusCode(), Strategy.INTROSPECTION);

        } catch (Exception e) {
            LOGGER.error("❌ Error validating token via introspection: {}", e.getMessage(), e);
            return new TokenValidationResult(false,
                "Error during token introspection: " + e.getMessage(), Strategy.INTROSPECTION);
        }
    }
}