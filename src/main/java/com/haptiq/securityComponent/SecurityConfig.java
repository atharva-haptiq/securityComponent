package com.haptiq.securityComponent;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // Disable CSRF (not needed for stateless API)
            .csrf(csrf -> csrf.disable())

            // All requests need authentication
            .authorizeHttpRequests(auth -> auth
                .anyRequest().authenticated()
            )

            // Stateless sessions (no cookies)
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )

            // Configure JWT authentication
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> {})  // Use default JWT configuration
            );

        return http.build();
    }
}
