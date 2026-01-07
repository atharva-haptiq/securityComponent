package com.haptiq.securityComponent;

import com.haptiq.securityComponent.model.TokenValidationResult;
import com.haptiq.securityComponent.service.TokenValidator;
import java.util.HashMap;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class HelloController {

    private final TokenValidator tokenValidator;

    public HelloController(TokenValidator tokenValidator) {
        this.tokenValidator = tokenValidator;
    }
    /**
     * Default endpoint using Spring Security (Strategy 2)
     */
    @GetMapping("/hello")
    public Map<String, Object> hello(@AuthenticationPrincipal Jwt jwt) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "✅ You are authenticated!");
        response.put("username", jwt.getClaimAsString("preferred_username"));
        response.put("email", jwt.getClaimAsString("email"));
        response.put("strategy", "SPRING_SECURITY_DEFAULT");
        return response;
    }

    @PostMapping("/validate-custom")
    public Map<String, Object> validateCustomToken(@RequestHeader ("Authorization") String authHeader) {
        String token = authHeader.replace("Bearer ", "");
        TokenValidationResult validationResult = tokenValidator.validateResult(token);
        Map<String, Object> response = new HashMap<>();
        response.put("valid", validationResult.isValid());
        response.put("strategy", validationResult.getStrategy().name());
        if (validationResult.isValid()) {
            response.put("message", "✅ Token is valid!");
            response.put("username", validationResult.getUserName());
            response.put("email", validationResult.getEmail());
            response.put("expiresAt", validationResult.getExpiresAt());
            response.put("claims", validationResult.getClaims());
        } else {
            response.put("message", "❌ Token is invalid: " + validationResult.getErrorMessage());
        }
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