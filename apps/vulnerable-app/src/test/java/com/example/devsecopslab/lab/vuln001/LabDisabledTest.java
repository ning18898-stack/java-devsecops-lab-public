package com.example.devsecopslab.lab.vuln001;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.webmvc.test.autoconfigure.MockMvcPrint;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.context.ApplicationContext;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;

@SpringBootTest(properties = "lab.vuln001.enabled=false")
@AutoConfigureMockMvc(print = MockMvcPrint.NONE)
class LabDisabledTest {
    @Autowired MockMvc mvc;
    @Autowired ApplicationContext context;

    @Test
    void defaultApplicationHasNoLabEndpointOrDatabase() throws Exception {
        mvc.perform(get("/api/labs/vuln001/articles/search").param("q", "' OR '1'='1").with(user("synthetic").roles("USER")))
                .andExpect(status().isNotFound());
        assertThat(context.getBeansOfType(LabDatabase.class)).isEmpty();
    }
}
