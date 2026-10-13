package com.example.devsecopslab.config;

import com.example.devsecopslab.security.SecurityResponseWriter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http, SecurityResponseWriter responses) throws Exception {
        http.authorizeHttpRequests(access -> access
                .requestMatchers(HttpMethod.GET, "/api/auth/csrf", "/actuator/health").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/auth/register", "/api/auth/login").permitAll()
                .requestMatchers("/api/users/**", "/api/articles/**").hasAnyRole("USER", "ADMIN")
                .anyRequest().authenticated());
        // Keep the default session CSRF token repository and session-fixation protection.
        http.formLogin(login -> login.loginProcessingUrl("/api/auth/login")
                .successHandler((request, response, authentication) -> responses.success(response, "Login successful"))
                .failureHandler((request, response, exception) -> responses.error(request, response,
                        HttpStatus.UNAUTHORIZED, "Invalid credentials")));
        http.logout(logout -> logout.logoutUrl("/api/auth/logout")
                .invalidateHttpSession(true).clearAuthentication(true).deleteCookies("JSESSIONID")
                .logoutSuccessHandler((request, response, authentication) -> responses.success(response, "Logout successful")));
        http.exceptionHandling(errors -> errors
                .authenticationEntryPoint((request, response, exception) -> responses.error(request, response,
                        HttpStatus.UNAUTHORIZED, "Authentication required"))
                .accessDeniedHandler((request, response, exception) -> responses.error(request, response,
                        HttpStatus.FORBIDDEN, "Access denied")));
        http.requestCache(cache -> cache.disable());
        return http.build();
    }
}
