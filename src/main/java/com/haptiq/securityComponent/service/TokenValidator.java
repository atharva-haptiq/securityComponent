package com.haptiq.securityComponent.service;

import com.haptiq.securityComponent.model.TokenValidationResult;

public interface TokenValidator {
    public TokenValidationResult validateResult(String token);
}
