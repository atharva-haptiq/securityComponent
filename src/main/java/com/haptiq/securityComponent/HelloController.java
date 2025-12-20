package com.haptiq.securityComponent;

import java.util.HashMap;
import java.util.Map;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class HelloController {

    /**
     * Simple hello endpoint
     */
    @GetMapping("/hello")
    public Map<String, Object> hello(@AuthenticationPrincipal Jwt jwt) {
        String username = jwt.getClaimAsString("preferred_username");

        Map<String, Object> response = new HashMap<>();
        response.put("message", "✅ You are authorized!");
        response.put("username", username);
        response.put("email", jwt.getClaimAsString("email"));

        return response;
    }

    /**
     * Validate token endpoint
     */
    @PostMapping("/validate-token")
    public Map<String, Object> validateToken(@AuthenticationPrincipal Jwt jwt) {
        Map<String, Object> response = new HashMap<>();
        response.put("valid", true);
        response.put("message", "✅ Token is valid!");

        Map<String, Object> user = new HashMap<>();
        user.put("username", jwt.getClaimAsString("preferred_username"));
        user.put("email", jwt.getClaimAsString("email"));
        user.put("name", jwt.getClaimAsString("name"));
        user.put("sub", jwt.getSubject());

        response.put("user", user);
        response.put("expiresAt", jwt.getExpiresAt());
        response.put("issuer", jwt.getIssuer());

        return response;
    }

    /**
     * Get user info
     */
    @GetMapping("/user-info")
    public Map<String, Object> userInfo(@AuthenticationPrincipal Jwt jwt) {
        Map<String, Object> response = new HashMap<>();
        response.put("username", jwt.getClaimAsString("preferred_username"));
        response.put("email", jwt.getClaimAsString("email"));
        response.put("name", jwt.getClaimAsString("name"));
        response.put("sub", jwt.getSubject());
        response.put("realmAccess", jwt.getClaim("realm_access"));
        response.put("clientRoles", jwt.getClaim("resource_access"));

        return response;
    }

    /**
     */
    @GetMapping("/health")
    public Map<String, Object> health() {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "ok");
        response.put("message", "Backend is running");
        response.put("timestamp", System.currentTimeMillis());

        return response;
    }
}