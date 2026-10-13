package com.example.devsecopslab.lab.vuln001;

import java.util.List;
import java.util.Map;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Profile;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Profile("vuln001-local")
@ConditionalOnProperty(name = "lab.vuln001.enabled", havingValue = "true")
@RequestMapping("/api/labs/vuln001")
public class LabController {
    private final LabService service;

    public LabController(LabService service) { this.service = service; }

    @GetMapping("/info")
    public Map<String, String> info() {
        return Map.of("labId", "VULN-001", "variant", "vulnerable", "fixtures", "v1", "mode", "local-readonly");
    }

    @GetMapping("/articles/search")
    public List<LabArticle> search(@RequestParam(value = "q", required = false) @NotBlank @Size(max = 200) String query) {
        return service.search(query);
    }
}
