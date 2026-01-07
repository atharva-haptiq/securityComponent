package com.haptiq.securityComponent.service;

import com.haptiq.securityComponent.Strategy;
import com.haptiq.securityComponent.model.TokenValidationResult;
import com.haptiq.securityComponent.service.strategy.IntrospectionValidationService;
import com.haptiq.securityComponent.service.strategy.LocalJWKSValidationService;
import com.haptiq.securityComponent.service.strategy.RemoteJWKSValidationService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class TokenValidationServiceImpl implements TokenValidator{

    private static final Logger LOGGER = LoggerFactory.getLogger(TokenValidationServiceImpl.class);

    @Value("${token.validation.strategy}")
    private Strategy strategy;

    private final LocalJWKSValidationService localJWKSValidationService;
    private final RemoteJWKSValidationService remoteJWKSValidationService;
    private final IntrospectionValidationService introspectionValidationService;

    public TokenValidationServiceImpl(LocalJWKSValidationService localJWKSValidationService,
        RemoteJWKSValidationService remoteJWKSValidationService,
        IntrospectionValidationService introspectionValidationService) {
        this.localJWKSValidationService = localJWKSValidationService;
        this.remoteJWKSValidationService = remoteJWKSValidationService;
        this.introspectionValidationService = introspectionValidationService;
    }


    @Override
    public TokenValidationResult validateResult(String token) {
        LOGGER.debug("Validating token using strategy: {}", strategy);
        return switch (strategy) {
            case LOCAL_JWKS -> localJWKSValidationService.validate(token);
            case REMOTE_JWKS -> remoteJWKSValidationService.validate(token);
            case INTROSPECTION -> introspectionValidationService.validate(token);
            default -> {
                LOGGER.error("Unsupported token validation strategy: {}", strategy);
                yield new TokenValidationResult(false, "Unsupported validation strategy", strategy);
            }
        };
    }
}
