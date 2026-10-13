package com.example.securelab;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.SecurityFilterChain;
@Configuration(proxyBeanMethods = false)
public class LegacySecurityConfiguration {
    @Bean UserDetailsService legacyNoUsers() { return name -> { throw new UsernameNotFoundException("No legacy login"); }; }
    @Bean @Order(100) SecurityFilterChain legacyChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(access -> access.anyRequest().permitAll());
        return http.build();
    }
}
