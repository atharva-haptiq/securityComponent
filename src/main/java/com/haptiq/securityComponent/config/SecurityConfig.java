package com.haptiq.securityComponent.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Value("${token.validation.keycloak.jwks-uri}")
    private String jwksUri;

    /**
     * JwtDecoder Bean
     *
     * Spring Security requires this bean to validate JWT tokens.
     * It fetches public keys from Keycloak's JWKS endpoint and caches them.
     */
    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withJwkSetUri(jwksUri).build();
    }

    /**
     * Security Filter Chain
     *
     * Configures security rules:
     * - Public endpoints: /api/health, /api/validate-custom, /api/validate-all
     * - All other endpoints require authentication
     * - Stateless sessions (no cookies)
     * - JWT-based authentication
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // Disable CSRF for stateless APIs
            .csrf(csrf -> csrf.disable())

            // Configure authorization rules
            .authorizeHttpRequests(auth -> auth
                // Public endpoints (no auth required)
                .requestMatchers("/api/health").permitAll()
                .requestMatchers("/api/validate-custom").permitAll()
                .requestMatchers("/api/validate-all").permitAll()

                // All other endpoints require authentication
                .anyRequest().authenticated()
            )

            // Stateless session management
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )

            // Configure OAuth2 Resource Server with JWT
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.decoder(jwtDecoder()))  // Use our JwtDecoder bean
            );

        return http.build();
    }
}