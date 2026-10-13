package com.example.securelab.vuln002;
import java.util.Map;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.webmvc.test.autoconfigure.MockMvcPrint;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import tools.jackson.databind.json.JsonMapper;
import static org.assertj.core.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
@SpringBootTest(properties={"lab.vuln002.enabled=true", "spring.profiles.include=vuln002-local", "lab.vuln002.schema=lab_vuln002_secure_test"})
@AutoConfigureMockMvc(print=MockMvcPrint.NONE)
class IdorArticleTest {
    static final String ROOT="/api/labs/vuln002";
    @Autowired MockMvc mvc;
    @Autowired JsonMapper json;
    @Autowired IdorDatabase database;
    IdorTestData data, other;
    long target, control, otherTarget;
    Map<String,Object> targetBefore, controlBefore, otherBefore;
    @BeforeEach void prepare() throws Exception {
        data=new IdorTestData(); other=new IdorTestData();
        target=data.article(data.aliceId,"Alice target"); control=data.article(data.bobId,"Bob control");
        otherTarget=other.article(other.aliceId,"Other run guardian");
        targetBefore=data.snapshot(target); controlBefore=data.snapshot(control); otherBefore=other.snapshot(otherTarget);
    }
    @AfterEach void cleanup() throws Exception {
        try {
            assertThat(data.snapshot(control)).isEqualTo(controlBefore);
            assertThat(other.snapshot(otherTarget)).isEqualTo(otherBefore);
        } finally { data.close(); other.close(); }
    }
    MockHttpSession session() throws Exception {
        return (MockHttpSession)mvc.perform(get(ROOT+"/auth/csrf")).andExpect(status().isOk()).andReturn().getRequest().getSession(false);
    }
    String token(MockHttpSession session) throws Exception {
        return json.readTree(mvc.perform(get(ROOT+"/auth/csrf").session(session)).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString()).path("token").asString();
    }
    MockHttpSession login(String name) throws Exception {
        var session=session();
        mvc.perform(post(ROOT+"/auth/login").session(session).header("X-CSRF-TOKEN",token(session))
                .param("username",name).param("password",data.password)).andExpect(status().isOk());
        return session;
    }
    String body(String title,String content) throws Exception { return json.writeValueAsString(Map.of("title",title,"content",content)); }
    void update(MockHttpSession session,long id,String body,int expected) throws Exception {
        mvc.perform(put(ROOT+"/articles/"+id).session(session).header("X-CSRF-TOKEN",token(session))
                .contentType("application/json").content(body)).andExpect(status().is(expected));
    }
    void unchanged() throws Exception { assertThat(data.snapshot(target)).isEqualTo(targetBefore); }
    void changed(String title,String content) throws Exception {
        var row=data.snapshot(target);
        assertThat(row.get("title")).isEqualTo(title); assertThat(row.get("content")).isEqualTo(content);
        assertThat(row.get("id")).isEqualTo(targetBefore.get("id"));
        assertThat(row.get("user_id")).isEqualTo(data.aliceId);
        assertThat(row.get("created_at")).isEqualTo(targetBefore.get("created_at"));
        assertThat(row.get("updated_at")).isNotEqualTo(targetBefore.get("updated_at"));
    }
    @Test void ownerCanModifyCommittedContent() throws Exception {
        update(login(data.alice),target,body("Alice changed","Owner content"),200); changed("Alice changed","Owner content");
    }
    @Test void bobCanReadAliceArticle() throws Exception {
        mvc.perform(get(ROOT+"/articles/"+target).session(login(data.bob))).andExpect(status().isOk())
                .andExpect(jsonPath("$.userId").value(data.aliceId)); unchanged();
    }
    @Test void crossUserWriteHasExpectedVariantAndIndependentDatabaseEvidence() throws Exception {
        update(login(data.bob),target,body("Bob changed","Unauthorized content"),403);
        unchanged();
    }
    @Test void anonymousReadAndWriteFailWithoutMutation() throws Exception {
        mvc.perform(get(ROOT+"/articles/"+target)).andExpect(status().isUnauthorized());
        update(session(),target,body("anonymous","blocked"),401); unchanged();
    }
    @Test void csrfFailurePreventsDatabaseWrite() throws Exception {
        var session=login(data.alice);
        mvc.perform(put(ROOT+"/articles/"+target).session(session).contentType("application/json").content(body("csrf","blocked")))
                .andExpect(status().isForbidden());
        mvc.perform(put(ROOT+"/articles/"+target).session(session).header("X-CSRF-TOKEN","invalid")
                .contentType("application/json").content(body("csrf","blocked"))).andExpect(status().isForbidden()); unchanged();
    }
    @Test void ownerAndIdentityFieldsAreRejected() throws Exception {
        var session=login(data.bob);
        for(String field:java.util.List.of("ownerId","userId","id","runId","role")) {
            var input=new java.util.HashMap<String,Object>(Map.of("title","spoof","content","blocked")); input.put(field,data.aliceId);
            update(session,target,json.writeValueAsString(input),400); unchanged();
        }
    }
    @Test void clientIdentityHeaderCannotChangeAuthenticatedPrincipalOrOwner() throws Exception {
        var session=login(data.bob);
        mvc.perform(put(ROOT+"/articles/"+target).session(session).header("X-CSRF-TOKEN",token(session))
                .header("X-User-ID",Long.toString(data.aliceId)).param("currentUserId",Long.toString(data.aliceId))
                .contentType("application/json").content(body("header spoof","still Bob"))).andExpect(status().is(403));
        mvc.perform(get(ROOT+"/auth/me").session(session)).andExpect(jsonPath("$.id").value(data.bobId));
        unchanged();
    }
    @Test void missingObjectReturns404AndDoesNotInsert() throws Exception {
        long missing;
        try(var connection=data.connection("reader");var statement=connection.createStatement();var rows=statement.executeQuery("SELECT COALESCE(MAX(id),0)+1 FROM lab_articles")) {
            rows.next();missing=rows.getLong(1);
        }
        var session=login(data.alice);
        mvc.perform(get(ROOT+"/articles/"+missing).session(session)).andExpect(status().isNotFound());
        update(session,missing,body("missing","blocked"),404); assertThat(data.snapshot(missing)).isEmpty(); unchanged();
    }
    @Test void anotherRunCannotBeReadOrModified() throws Exception {
        var session=login(data.bob);
        mvc.perform(get(ROOT+"/articles/"+otherTarget).session(session)).andExpect(status().isNotFound());
        update(session,otherTarget,body("other run","blocked"),404); unchanged();
    }
    @Test void malformedInputDoesNotModifyDatabase() throws Exception {
        var session=login(data.alice);
        for(String content:java.util.List.of("", "x".repeat(20001), "\u754c".repeat(20000)+"\u754c")) {
            update(session,target,body("invalid",content),400); unchanged();
        }
        update(session,target,body("x".repeat(201),"invalid"),400);
        mvc.perform(get(ROOT+"/articles/not-a-number").session(session)).andExpect(status().isBadRequest()); unchanged();
    }
    @Test void repeatedIdenticalOwnerPutStillSucceeds() throws Exception {
        var session=login(data.alice);
        update(session,target,body("same","same"),200); update(session,target,body("same","same"),200); changed("same","same");
    }
    @Test void mapperHasAtomicVariantAuthorization() throws Exception {
        try(var session=database.openTransaction()) {
            int count=session.getMapper(IdorMapper.class).update(target,data.run,data.bobId,"Direct mapper","Bound values");
            assertThat(count).isEqualTo(0); session.commit();
        }
        unchanged();
        var parameters=new java.util.HashMap<String,Object>();
        parameters.put("id",target);parameters.put("runId",data.run);parameters.put("currentUserId",data.bobId);
        parameters.put("title","' OR '1'='1");parameters.put("content","bound");
        var bound=database.configuration().getMappedStatement(IdorMapper.class.getName()+".update").getBoundSql(parameters);
        assertThat(bound.getSql()).doesNotContain("' OR '1'='1");
        assertThat(bound.getParameterMappings().stream().map(p -> p.getProperty()).toList()).contains("currentUserId");
    }
    @Test void uncommittedUpdateRollsBack() throws Exception {
        try(var session=database.openTransaction()) {
            session.getMapper(IdorMapper.class).update(target,data.run,data.aliceId,"rollback","not committed");
        }
        unchanged();
    }
}
