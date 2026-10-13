package com.example.devsecopslab.lab.vuln002;
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
@SpringBootTest(properties={"lab.vuln002.enabled=true", "spring.profiles.include=vuln002-local", "lab.vuln002.schema=lab_vuln002_vulnerable_test"})
@AutoConfigureMockMvc(print=MockMvcPrint.NONE)
class IdorAuthTest {
    static final String ROOT="/api/labs/vuln002";
    @Autowired MockMvc mvc;
    @Autowired JsonMapper json;
    IdorTestData data;
    @BeforeEach void prepare() throws Exception { data = new IdorTestData(); }
    @AfterEach void cleanup() throws Exception { data.close(); }
    MockHttpSession session() throws Exception {
        return (MockHttpSession)mvc.perform(get(ROOT+"/auth/csrf")).andExpect(status().isOk()).andReturn().getRequest().getSession(false);
    }
    String token(MockHttpSession session) throws Exception {
        return json.readTree(mvc.perform(get(ROOT+"/auth/csrf").session(session)).andExpect(status().isOk()).andReturn().getResponse().getContentAsString()).path("token").asString();
    }
    void login(MockHttpSession session,String name) throws Exception {
        mvc.perform(post(ROOT+"/auth/login").session(session).header("X-CSRF-TOKEN",token(session))
                .param("username",name).param("password",data.password)).andExpect(status().isOk());
    }
    @Test void realLoginHasImmutableIdAndNoHash() throws Exception {
        var session=session(); login(session,data.alice);
        mvc.perform(get(ROOT+"/auth/me").session(session)).andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(data.aliceId)).andExpect(jsonPath("$.passwordHash").doesNotExist());
        var principal=(org.springframework.security.core.context.SecurityContext)session.getAttribute("VULN002_SECURITY_CONTEXT");
        assertThat(((IdorPrincipal)principal.getAuthentication().getPrincipal()).getPassword()).isNull();
        assertThat(session.getAttribute("SPRING_SECURITY_CONTEXT")).isNull();
    }
    @Test void unknownAndWrongCredentialsBoth401() throws Exception {
        var session=session();
        for(String name:java.util.List.of(data.alice,"unknown")) {
            mvc.perform(post(ROOT+"/auth/login").session(session).header("X-CSRF-TOKEN",token(session))
                    .param("username",name).param("password","incorrect")).andExpect(status().isUnauthorized());
        }
    }
    @Test void anonymousCannotReadIdentity() throws Exception {
        mvc.perform(get(ROOT+"/auth/me")).andExpect(status().isUnauthorized());
    }
    @Test void missingCsrfBlocksLoginAndLogout() throws Exception {
        var session=session();
        mvc.perform(post(ROOT+"/auth/login").session(session).param("username",data.alice).param("password",data.password))
                .andExpect(status().isForbidden());
        login(session,data.alice);
        mvc.perform(post(ROOT+"/auth/logout").session(session)).andExpect(status().isForbidden());
        mvc.perform(get(ROOT+"/auth/me").session(session)).andExpect(status().isOk());
    }
    @Test void sessionFixationAndOldTokenAreBlocked() throws Exception {
        var session=session(); String id=session.getId(); String old=token(session);
        login(session,data.alice); assertThat(session.getId()).isNotEqualTo(id);
        mvc.perform(post(ROOT+"/auth/logout").session(session).header("X-CSRF-TOKEN",old)).andExpect(status().isForbidden());
        mvc.perform(post(ROOT+"/auth/logout").session(session).header("X-CSRF-TOKEN",token(session))).andExpect(status().isOk());
        mvc.perform(get(ROOT+"/auth/me").session(session)).andExpect(status().isUnauthorized());
    }
    @Test void legacyContextCannotAuthenticateLabEvenWithSameUsername() throws Exception {
        var session=session();
        var legacy=org.springframework.security.core.context.SecurityContextHolder.createEmptyContext();
        legacy.setAuthentication(new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
                org.springframework.security.core.userdetails.User.withUsername(data.alice).password("unused").roles("USER").build(),
                null,java.util.List.of(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_USER"))));
        session.setAttribute("SPRING_SECURITY_CONTEXT",legacy);
        mvc.perform(get(ROOT+"/auth/me").session(session)).andExpect(status().isUnauthorized());
    }
    @Autowired org.springframework.jdbc.core.JdbcTemplate baseline;
    @Test void experimentLoginCannotAccessBaselineOrVuln001() throws Exception {
        var session=session(); login(session,data.alice);
        mvc.perform(get("/api/users/me").session(session)).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/labs/vuln001/info").session(session)).andExpect(status().isUnauthorized());
    }
    @Test void realBaselineLoginSurvivesLabLoginAndLogout() throws Exception {
        String name="v002_"+data.run.substring(0,12);
        var initial=mvc.perform(get("/api/auth/csrf")).andExpect(status().isOk()).andReturn();
        var session=(MockHttpSession)initial.getRequest().getSession(false);
        String csrf=json.readTree(initial.getResponse().getContentAsString()).path("token").asString();
        try {
            mvc.perform(post("/api/auth/register").session(session).header("X-CSRF-TOKEN",csrf).contentType("application/json")
                    .content(json.writeValueAsString(java.util.Map.of("username",name,"email",name+"@example.test","password",data.password))))
                    .andExpect(status().isCreated());
            mvc.perform(post("/api/auth/login").session(session).header("X-CSRF-TOKEN",csrf).param("username",name).param("password",data.password))
                    .andExpect(status().isOk());
            mvc.perform(get(ROOT+"/auth/me").session(session)).andExpect(status().isUnauthorized());
            login(session,data.alice);
            mvc.perform(get("/api/users/me").session(session)).andExpect(status().isOk()).andExpect(jsonPath("$.username").value(name));
            mvc.perform(post(ROOT+"/auth/logout").session(session).header("X-CSRF-TOKEN",token(session))).andExpect(status().isOk());
            mvc.perform(get("/api/users/me").session(session)).andExpect(status().isOk()).andExpect(jsonPath("$.username").value(name));
        } finally { baseline.update("DELETE FROM app_users WHERE username=?",name); }
    }

}
