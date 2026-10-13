package com.example.devsecopslab.lab.vuln002;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import static org.assertj.core.api.Assertions.*;
@SpringBootTest(properties="lab.vuln002.enabled=false")
class IdorDisabledTest {
    @Autowired ApplicationContext context;
    @Test void noComponentsByDefault() {
        assertThat(context.getBeansOfType(IdorDatabase.class)).isEmpty();
        assertThat(context.getBeansOfType(IdorAuthController.class)).isEmpty();
        assertThat(context.getBeansOfType(IdorSecurity.class)).isEmpty();
        assertThat(context.getBeansOfType(IdorArticleController.class)).isEmpty();
        assertThat(context.getBeansOfType(IdorService.class)).isEmpty();
        assertThat(context.getBeansOfType(IdorErrors.class)).isEmpty();
    }
}
