package com.example.securelab.vuln002;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Positive;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Profile;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
@RestController
@Profile("vuln002-local")
@ConditionalOnProperty(name="lab.vuln002.enabled",havingValue="true")
@RequestMapping("/api/labs/vuln002/articles")
public class IdorArticleController {
    private final IdorService service;
    public IdorArticleController(IdorService service) { this.service=service; }
    @GetMapping("/{id}") public IdorArticle find(@PathVariable @Positive long id,
            @AuthenticationPrincipal IdorPrincipal principal) { return service.find(id,principal); }
    @PutMapping("/{id}") public IdorArticle update(@PathVariable @Positive long id,
            @AuthenticationPrincipal IdorPrincipal principal, @Valid @RequestBody IdorRequest request) {
        return service.update(id,principal,request);
    }
}
