package com.quiz.config;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableMethodSecurity
public class SecurityConfiguration {  //bind the filter

    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
             http.cors(corsCustomizer -> corsCustomizer.configurationSource(new CorsConfigurationSource() {
                         @Override
                         public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                             CorsConfiguration config = new CorsConfiguration();
                             config.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
                             config.setAllowedMethods(Collections.singletonList("*"));
                             config.setAllowCredentials(true);
                             config.setAllowedHeaders(Collections.singletonList("*"));
                             config.setMaxAge(3600L);
                             return config;
                         }
                     }))
                .csrf(AbstractHttpConfigurer::disable) // disables CSRF (Cross-Site Request Forgery) protection
                        .authorizeHttpRequests((authz) -> authz
                             .requestMatchers("/api/v1/auth/**").permitAll() //whitelist, no auth required
                                .anyRequest().authenticated()) //all other requests need auth
                .sessionManagement((session)->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) //new session for each request
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}
