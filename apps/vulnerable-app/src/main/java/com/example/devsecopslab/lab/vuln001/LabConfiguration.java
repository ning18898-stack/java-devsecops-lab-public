package com.example.devsecopslab.lab.vuln001;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;

@Configuration(proxyBeanMethods = false)
@Profile("vuln001-local")
@ConditionalOnProperty(name = "lab.vuln001.enabled", havingValue = "true")
public class LabConfiguration {
    @Bean(destroyMethod = "close")
    LabDatabase labDatabase(Environment environment) {
        String url = environment.getRequiredProperty("lab.vuln001.url");
        String username = environment.getRequiredProperty("lab.vuln001.username");
        boolean test = LabGuard.verify(environment, url, username);
        String password = environment.getRequiredProperty("lab.vuln001.password");
        if (!test && password.isBlank()) {
            throw new IllegalStateException("VULN-001 database password is required");
        }
        return new LabDatabase(url, username, password, test);
    }

    @Bean
    LabService labService(LabDatabase database) { return new LabService(database); }
}
