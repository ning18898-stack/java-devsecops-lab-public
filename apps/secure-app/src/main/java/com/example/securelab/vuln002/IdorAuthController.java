package com.example.securelab.vuln002;
import java.util.Map;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Profile;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
@RestController
@Profile("vuln002-local")
@ConditionalOnProperty(name = "lab.vuln002.enabled", havingValue = "true")
@RequestMapping("/api/labs/vuln002")
public class IdorAuthController {
    @GetMapping("/auth/csrf") public Map<String, String> csrf(CsrfToken token) {
        return Map.of("token", token.getToken(), "headerName", token.getHeaderName());
    }
    @GetMapping("/auth/me") public Map<String, Object> me(@AuthenticationPrincipal IdorPrincipal principal) {
        return Map.of("id", principal.getId(), "username", principal.getUsername());
    }
    @GetMapping("/info") public Map<String, String> info() {
        return Map.of("labId", "VULN-002", "variant", "secure", "fixtures", "v1");
    }
}
