package com.example.securelab.vuln002;
import java.io.IOException;
import java.util.Map;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
@Configuration(proxyBeanMethods = false)
@Profile("vuln002-local")
@ConditionalOnProperty(name = "lab.vuln002.enabled", havingValue = "true")
public class IdorSecurity {
    public static final String ROOT = "/api/labs/vuln002";
    @Bean @Order(1)
    SecurityFilterChain idorChain(HttpSecurity http, IdorDatabase database) throws Exception {
        var contexts = new HttpSessionSecurityContextRepository();
        contexts.setSpringSecurityContextKey("VULN002_SECURITY_CONTEXT");
        var tokens = new HttpSessionCsrfTokenRepository();
        tokens.setSessionAttributeName("VULN002_CSRF");
        var provider = new DaoAuthenticationProvider(name -> {
            var user = database.user(name);
            if (user == null) { throw new UsernameNotFoundException("Invalid credentials"); }
            return new IdorPrincipal(user);
        });
        provider.setPasswordEncoder(new BCryptPasswordEncoder(12));
        http.securityMatcher(ROOT + "/**")
                .authenticationManager(new ProviderManager(provider))
                .securityContext(context -> context.securityContextRepository(contexts))
                .csrf(csrf -> csrf.csrfTokenRepository(tokens))
                .authorizeHttpRequests(access -> access
                    .requestMatchers(ROOT + "/auth/csrf", ROOT + "/auth/login").permitAll()
                    .anyRequest().hasRole("USER"))
                .formLogin(login -> login.loginProcessingUrl(ROOT + "/auth/login")
                    .successHandler((req, res, auth) -> reply(res, 200, "Login successful"))
                    .failureHandler((req, res, error) -> reply(res, 401, "Invalid credentials")))
                .logout(logout -> logout.logoutUrl(ROOT + "/auth/logout")
                    .invalidateHttpSession(false).clearAuthentication(false)
                    .addLogoutHandler((req, res, auth) -> {
                        var empty = org.springframework.security.core.context.SecurityContextHolder.createEmptyContext();
                        contexts.saveContext(empty, req, res);
                        tokens.saveToken(null, req, res);
                    })
                    .logoutSuccessHandler((req, res, auth) -> reply(res, 200, "Logout successful")))
                .exceptionHandling(errors -> errors
                    .authenticationEntryPoint((req, res, error) -> reply(res, 401, "Authentication required"))
                    .accessDeniedHandler((req, res, error) -> reply(res, 403, "Access denied")))
                .requestCache(cache -> cache.disable());
        return http.build();
    }
    private static void reply(HttpServletResponse response, int status, String message) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        response.getWriter().write("{\"status\":" + status + ",\"message\":\"" + message + "\"}");
    }
}
