package com.example.devsecopslab.lab.vuln002;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
@Configuration(proxyBeanMethods = false)
@Profile("vuln002-local")
@ConditionalOnProperty(name = "lab.vuln002.enabled", havingValue = "true")
public class IdorConfiguration {
    @Bean(destroyMethod = "close") IdorDatabase idorDatabase(Environment env) { return new IdorDatabase(env); }
    @Bean IdorService idorService(IdorDatabase database) { return new IdorService(database); }
}
