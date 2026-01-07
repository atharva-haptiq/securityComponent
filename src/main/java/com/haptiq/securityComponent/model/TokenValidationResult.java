package com.haptiq.securityComponent.model;

import com.haptiq.securityComponent.Strategy;
import java.time.Instant;
import java.util.Map;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class TokenValidationResult {

    private boolean valid;
    private String userName;
    private String email;
    private Instant expiresAt;
    private Strategy strategy;
    private String errorMessage;
    private Map<String, Object> claims;

    public TokenValidationResult(boolean valid, Strategy strategy) {
        this.valid = valid;
        this.strategy = strategy;
    }

    public TokenValidationResult(boolean valid, String errorMessage, Strategy strategy) {
        this.valid = valid;
        this.errorMessage = errorMessage;
        this.strategy = strategy;
    }

    public TokenValidationResult() {

    }
}

