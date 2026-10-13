package com.example.devsecopslab;

import com.example.devsecopslab.entity.Role;
import com.example.devsecopslab.entity.User;
import com.example.devsecopslab.mapper.ArticleMapper;
import com.example.devsecopslab.security.LabPrincipal;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.webmvc.test.autoconfigure.MockMvcPrint;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc(print = MockMvcPrint.NONE)
class ErrorHandlingTest {
    @Autowired MockMvc mvc;
    @MockitoBean ArticleMapper articles;

    @Test
    void unexpectedDatabaseFailureReturnsOnlySanitizedError() throws Exception {
        when(articles.findById(1L)).thenThrow(new DataAccessResourceFailureException(
                "SELECT password_hash FROM app_users; C:/internal/path; fake-secret-marker"));
        User account = new User();
        account.setId(1L);
        account.setUsername("synthetic");
        account.setRole(Role.USER);
        String response = mvc.perform(get("/api/articles/1").with(user(new LabPrincipal(account))))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.status").value(500))
                .andExpect(jsonPath("$.error").value("Internal Server Error"))
                .andExpect(jsonPath("$.message").value("Internal server error"))
                .andExpect(jsonPath("$.path").value("/api/articles/1"))
                .andExpect(jsonPath("$.timestamp").isString())
                .andExpect(jsonPath("$.trace").doesNotExist())
                .andReturn().getResponse().getContentAsString();
        assertThat(response).doesNotContain("SELECT", "password", "fake-secret", "internal/path", "Exception", "mapper");
    }
}
