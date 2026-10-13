package com.example.devsecopslab.lab.vuln001;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.webmvc.test.autoconfigure.MockMvcPrint;
import org.springframework.test.web.servlet.MockMvc;
import org.apache.ibatis.mapping.SqlCommandType;
import org.apache.ibatis.mapping.StatementType;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;

@SpringBootTest(properties = {"lab.vuln001.enabled=true", "spring.profiles.include=vuln001-local"})
@AutoConfigureMockMvc(print = MockMvcPrint.NONE)
class LabQueryTest {
    static final String PAYLOAD = "' OR '1'='1";
    static final String PATH = "/api/labs/vuln001/articles/search";
    @Autowired MockMvc mvc;
    @Autowired LabDatabase database;

    @Test
    void normalTitleReturnsOnlyMatchingPublicArticle() throws Exception {
        mvc.perform(get(PATH).param("q", "Alpha public article").with(user("synthetic").roles("USER")))
                .andExpect(status().isOk()).andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].id").value(1))
                .andExpect(jsonPath("$[0].visibility").value("public"));
    }

    @Test
    void normalDraftTitleRemainsHidden() throws Exception {
        mvc.perform(get(PATH).param("q", "Synthetic draft article").with(user("synthetic").roles("USER")))
                .andExpect(status().isOk()).andExpect(content().json("[]"));
    }

    @Test
    void identicalInjectionInputHasExpectedVariantSemantics() throws Exception {
        mvc.perform(get(PATH).param("q", PAYLOAD).with(user("synthetic").roles("USER")))
                .andExpect(status().isOk()).andExpect(jsonPath("$.length()").value(3));
        assertThat(database.search(PAYLOAD)).extracting(LabArticle::id)
                .containsExactly(1L, 2L, 3L);
    }

    @Test
    void falsePredicateDoesNotReturnRecords() throws Exception {
        mvc.perform(get(PATH).param("q", "' OR '1'='2").with(user("synthetic").roles("USER")))
                .andExpect(status().isOk()).andExpect(content().json("[]"));
    }

    @Test
    void missingAndOversizedInputAreRejected() throws Exception {
        mvc.perform(get(PATH).with(user("synthetic").roles("USER"))).andExpect(status().isBadRequest());
        mvc.perform(get(PATH).param("q", " ").with(user("synthetic").roles("USER"))).andExpect(status().isBadRequest());
        mvc.perform(get(PATH).param("q", "x".repeat(201)).with(user("synthetic").roles("USER")))
                .andExpect(status().isBadRequest());
    }

    @Test
    void injectionDoesNotModifyFixtureAndSubsequentQueryStillWorks() {
        database.search(PAYLOAD);
        assertThat(database.search("Alpha public article")).extracting(LabArticle::id).containsExactly(1L);
        assertThat(database.search("Synthetic draft article")).isEmpty();
        assertThat(database.search("Unknown article")).isEmpty();
    }

    @Test
    void sqlStructureAndParameterMappingsExplainRootCauseOrFix() {
        var statement = database.configuration().getMappedStatement(LabArticleMapper.class.getName() + ".search");
        var bound = statement.getBoundSql(Map.of("query", PAYLOAD));
        assertThat(statement.getSqlCommandType()).isEqualTo(SqlCommandType.SELECT);
        assertThat(statement.getStatementType()).isEqualTo(StatementType.PREPARED);
        assertThat(bound.getSql()).contains(PAYLOAD);
        assertThat(bound.getParameterMappings()).isEmpty();
    }

    @Test
    void normalQueryUsesExpectedSqlConstruction() {
        var statement = database.configuration().getMappedStatement(LabArticleMapper.class.getName() + ".search");
        var bound = statement.getBoundSql(Map.of("query", "Alpha public article"));
        assertThat(bound.getSql()).contains("Alpha public article");
    }

    @Test
    void anonymousClientCannotReachLab() throws Exception {
        mvc.perform(get(PATH).param("q", PAYLOAD)).andExpect(status().isUnauthorized());
    }

    @Test
    void syntaxErrorIsSanitizedWithoutSqlOrStackTrace() throws Exception {
        mvc.perform(get(PATH).param("q", "'").with(user("synthetic").roles("USER")))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.message").value("Internal server error"))
                .andExpect(jsonPath("$.trace").doesNotExist());
    }
 }
