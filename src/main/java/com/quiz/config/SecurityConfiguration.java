package com.quiz.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;


@Configuration
public class SecurityConfiguration {

    @Autowired
    JWTTokenGeneratorFilter jwtTokenGeneratorFilter;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
             http.sessionManagement((session)->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                 .cors(corsCustomizer -> corsCustomizer.configurationSource(request -> {
                     CorsConfiguration config = new CorsConfiguration();
                     config.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
                     config.setAllowedMethods(Collections.singletonList("*"));
                     config.setAllowCredentials(true);
                     config.setAllowedHeaders(Collections.singletonList("*"));
                     config.setExposedHeaders(List.of("Authorization"));
                     config.setMaxAge(3600L);
                     return config;
                 })).csrf(AbstractHttpConfigurer::disable)
                     .addFilterBefore(new JWTTokenValidationFilter(), BasicAuthenticationFilter.class)
                     .addFilterAfter(jwtTokenGeneratorFilter, BasicAuthenticationFilter.class)
                        .authorizeHttpRequests((requests) -> requests
                                .requestMatchers("/api/v1/auth/authenticate", "/api/v1/auth/test").authenticated()
                                .requestMatchers("/api/v1/auth/register").permitAll())
                     .httpBasic(Customizer.withDefaults());
        return http.build();
    }
}
