package com.example.securelab.vuln001;

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

@SpringBootTest(properties = {"lab.vuln001.enabled=true", "spring.profiles.include=vuln001-local"})
@AutoConfigureMockMvc(print = MockMvcPrint.NONE)
class LabQueryTest {
    static final String PAYLOAD = "' OR '1'='1";
    static final String PATH = "/api/labs/vuln001/articles/search";
    @Autowired MockMvc mvc;
    @Autowired LabDatabase database;

    @Test
    void normalTitleReturnsOnlyMatchingPublicArticle() throws Exception {
        mvc.perform(get(PATH).param("q", "Alpha public article"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].id").value(1))
                .andExpect(jsonPath("$[0].visibility").value("public"));
    }

    @Test
    void normalDraftTitleRemainsHidden() throws Exception {
        mvc.perform(get(PATH).param("q", "Synthetic draft article"))
                .andExpect(status().isOk()).andExpect(content().json("[]"));
    }

    @Test
    void identicalInjectionInputHasExpectedVariantSemantics() throws Exception {
        mvc.perform(get(PATH).param("q", PAYLOAD))
                .andExpect(status().isOk()).andExpect(jsonPath("$.length()").value(0));
        assertThat(database.search(PAYLOAD)).extracting(LabArticle::id)
                .containsExactly();
    }

    @Test
    void falsePredicateDoesNotReturnRecords() throws Exception {
        mvc.perform(get(PATH).param("q", "' OR '1'='2"))
                .andExpect(status().isOk()).andExpect(content().json("[]"));
    }

    @Test
    void missingAndOversizedInputAreRejected() throws Exception {
        mvc.perform(get(PATH)).andExpect(status().isBadRequest());
        mvc.perform(get(PATH).param("q", " ")).andExpect(status().isBadRequest());
        mvc.perform(get(PATH).param("q", "x".repeat(201)))
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
        assertThat(bound.getSql()).doesNotContain(PAYLOAD).contains("title = ?");
        assertThat(bound.getParameterMappings()).extracting("property").containsExactly("query");
    }

    @Test
    void normalQueryUsesExpectedSqlConstruction() {
        var statement = database.configuration().getMappedStatement(LabArticleMapper.class.getName() + ".search");
        var bound = statement.getBoundSql(Map.of("query", "Alpha public article"));
        assertThat(bound.getSql()).doesNotContain("Alpha public article").contains("title = ?");
    }

    @Test
    void quotesWildcardsAndCommentsRemainLiteralData() throws Exception {
        for (String query : new String[] {"'", "%", "_", "--", "Alpha public article' OR '1'='1"}) {
            mvc.perform(get(PATH).param("q", query)).andExpect(status().isOk()).andExpect(content().json("[]"));
        }
    }
 }
