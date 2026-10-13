package com.example.devsecopslab;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Stream;
import com.example.devsecopslab.mapper.UserMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.webmvc.test.autoconfigure.MockMvcPrint;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc(print = MockMvcPrint.NONE)
class BaselineApiTest {
    @Autowired MockMvc mvc;
    @Autowired JsonMapper json;
    @Autowired JdbcTemplate jdbc;
    @Autowired UserMapper users;
    @Autowired PasswordEncoder encoder;
    private String password;

    @BeforeEach
    void resetSyntheticData() {
        // The mysql profile must point at the dedicated disposable lab_test database.
        assertThat(jdbc.getDataSource()).isNotNull();
        try (var connection = jdbc.getDataSource().getConnection()) {
            String url = connection.getMetaData().getURL();
            boolean inMemory = url.equals("jdbc:h2:mem:lab") || url.startsWith("jdbc:h2:mem:lab;");
            boolean isolatedMysql = connection.getMetaData().getDatabaseProductName().equals("MySQL")
                    && "lab_test".equals(connection.getCatalog());
            assertThat(inMemory || isolatedMysql).as("Require an isolated disposable test database").isTrue();
        } catch (java.sql.SQLException exception) {
            throw new IllegalStateException("Test database unavailable", exception);
        }
        jdbc.update("DELETE FROM articles");
        jdbc.update("DELETE FROM app_users");
        password = UUID.randomUUID().toString();
    }

    @Test
    void registerStoresBcryptAndReturnsOnlyPublicFields() throws Exception {
        JsonNode response = register("alice", "alice@example.test");
        var user = users.findByUsername("alice");
        assertThat(user.getRole().name()).isEqualTo("USER");
        assertThat(user.getPasswordHash()).isNotEqualTo(password).startsWith("$2a$12$");
        assertThat(encoder.matches(password, user.getPasswordHash())).isTrue();
        assertThat(response.path("id").asLong()).isPositive();
        assertThat(response.path("createdAt").asString()).isNotBlank();
        assertNoPassword(response);
    }

    @Test
    void duplicateUsernameIsRejectedAfterNormalization() throws Exception {
        register("alice", "alice@example.test");
        mvc.perform(post("/api/auth/register").with(csrf()).contentType(MediaType.APPLICATION_JSON)
                .content(body(Map.of("username", "ALICE", "email", "other@example.test", "password", password))))
                .andExpect(status().isConflict()).andExpect(jsonPath("$.status").value(409));
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM app_users", Integer.class)).isEqualTo(1);
    }

    @Test
    void duplicateEmailIsRejected() throws Exception {
        register("alice", "alice@example.test");
        mvc.perform(post("/api/auth/register").with(csrf()).contentType(MediaType.APPLICATION_JSON)
                .content(body(Map.of("username", "bob", "email", "ALICE@example.test", "password", password))))
                .andExpect(status().isConflict());
    }

    static Stream<Arguments> invalidRegistration() {
        return Stream.of(Arguments.of("username", "ab"), Arguments.of("username", "alice'--"),
                Arguments.of("email", "invalid"), Arguments.of("email", ""),
                Arguments.of("password", "short"), Arguments.of("password", "界".repeat(25)),
                Arguments.of("password", "x".repeat(73)));
    }

    @ParameterizedTest
    @MethodSource("invalidRegistration")
    void invalidRegistrationReturnsSanitized400(String field, String invalid) throws Exception {
        var input = new java.util.HashMap<String, String>(Map.of(
                "username", "alice", "email", "alice@example.test", "password", password));
        input.put(field, invalid);
        mvc.perform(post("/api/auth/register").with(csrf()).contentType(MediaType.APPLICATION_JSON).content(body(input)))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.message").value("Invalid request"))
                .andExpect(jsonPath("$.trace").doesNotExist());
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM app_users", Integer.class)).isZero();
    }

    @Test
    void cannotChooseAdminRoleOrInjectPasswordHash() throws Exception {
        mvc.perform(post("/api/auth/register").with(csrf()).contentType(MediaType.APPLICATION_JSON)
                .content(body(Map.of("username", "alice", "email", "alice@example.test", "password", password, "role", "ADMIN"))))
                .andExpect(status().isBadRequest());
        mvc.perform(post("/api/auth/register").with(csrf()).contentType(MediaType.APPLICATION_JSON)
                .content(body(Map.of("username", "alice", "email", "alice@example.test", "password", password, "passwordHash", "invalid"))))
                .andExpect(status().isBadRequest());
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM app_users", Integer.class)).isZero();
    }

    @Test
    void loginAndMeUsePersistedSession() throws Exception {
        JsonNode registered = register("alice", "alice@example.test");
        MockHttpSession session = login("alice");
        MvcResult result = mvc.perform(get("/api/users/me").session(session))
                .andExpect(status().isOk()).andExpect(jsonPath("$.id").value(registered.path("id").asLong()))
                .andReturn();
        assertNoPassword(node(result));
    }

    @Test
    void incorrectAndUnknownCredentialsReturnSame401() throws Exception {
        register("alice", "alice@example.test");
        for (String name : List.of("alice", "unknown")) {
            mvc.perform(post("/api/auth/login").with(csrf()).param("username", name)
                    .param("password", UUID.randomUUID().toString()))
                    .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.message").value("Invalid credentials"));
        }
    }

    @Test
    void loginWithOversizedPasswordFailsSafely() throws Exception {
        register("alice", "alice@example.test");
        for (String input : List.of("x".repeat(73), "界".repeat(25))) {
            mvc.perform(post("/api/auth/login").with(csrf()).param("username", "alice").param("password", input))
                    .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.message").value("Invalid credentials"))
                    .andExpect(jsonPath("$.trace").doesNotExist());
        }
    }

    @Test
    void profileUniquenessCannotBeBypassedDuringUpdate() throws Exception {
        register("alice", "alice@example.test");
        register("bob", "bob@example.test");
        MockHttpSession session = login("alice");
        for (Map<String, String> input : List.of(Map.of("username", "BOB", "email", "new@example.test"),
                Map.of("username", "renamed", "email", "BOB@example.test"))) {
            mvc.perform(put("/api/users/me").session(session).with(csrf())
                    .contentType(MediaType.APPLICATION_JSON).content(body(input)))
                    .andExpect(status().isConflict());
        }
        assertThat(users.findByUsername("alice").getEmail()).isEqualTo("alice@example.test");
        assertThat(users.findByUsername("bob").getEmail()).isEqualTo("bob@example.test");
    }

    @Test
    void realCsrfFlowRotatesSessionAndTokenAndLogoutInvalidatesSession() throws Exception {
        register("alice", "alice@example.test");
        MvcResult csrfResult = mvc.perform(get("/api/auth/csrf")).andExpect(status().isOk()).andReturn();
        MockHttpSession session = (MockHttpSession) csrfResult.getRequest().getSession(false);
        String originalId = session.getId();
        String oldToken = node(csrfResult).path("token").asString();
        mvc.perform(post("/api/auth/login").session(session).header("X-CSRF-TOKEN", oldToken)
                .param("username", "alice").param("password", password)).andExpect(status().isOk());
        assertThat(session.getId()).isNotEqualTo(originalId);
        MvcResult refreshed = mvc.perform(get("/api/auth/csrf").session(session)).andReturn();
        String token = node(refreshed).path("token").asString();
        mvc.perform(post("/api/articles").session(session).header("X-CSRF-TOKEN", oldToken)
                .contentType(MediaType.APPLICATION_JSON).content(articleBody("title", "content")))
                .andExpect(status().isForbidden());
        mvc.perform(post("/api/articles").session(session).header("X-CSRF-TOKEN", token)
                .contentType(MediaType.APPLICATION_JSON).content(articleBody("title", "content")))
                .andExpect(status().isCreated());
        mvc.perform(post("/api/auth/logout").session(session).header("X-CSRF-TOKEN", token))
                .andExpect(status().isOk());
        assertThat(session.isInvalid()).isTrue();
        mvc.perform(get("/api/users/me")).andExpect(status().isUnauthorized());
    }

    @Test
    void writesAndLoginRequireCsrf() throws Exception {
        register("alice", "alice@example.test");
        mvc.perform(post("/api/auth/login").param("username", "alice").param("password", password))
                .andExpect(status().isForbidden());
        MockHttpSession session = login("alice");
        mvc.perform(post("/api/articles").session(session).contentType(MediaType.APPLICATION_JSON)
                .content(articleBody("title", "content"))).andExpect(status().isForbidden());
        mvc.perform(post("/api/auth/logout").session(session)).andExpect(status().isForbidden());
    }

    static Stream<Arguments> protectedEndpoints() {
        return Stream.of(Arguments.of("GET", "/api/users/me"), Arguments.of("PUT", "/api/users/me"),
                Arguments.of("POST", "/api/articles"), Arguments.of("GET", "/api/articles"),
                Arguments.of("GET", "/api/articles/1"), Arguments.of("PUT", "/api/articles/1"),
                Arguments.of("DELETE", "/api/articles/1"), Arguments.of("GET", "/api/articles/search?q=test"));
    }

    @ParameterizedTest
    @MethodSource("protectedEndpoints")
    void anonymousCannotAccessProtectedEndpoints(String method, String path) throws Exception {
        mvc.perform(request(HttpMethod.valueOf(method), path).with(csrf())
                .contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.status").value(401));
    }

    @Test
    void profileUpdateKeepsStableIdentityAndExcludesPassword() throws Exception {
        long userId = register("alice", "alice@example.test").path("id").asLong();
        MockHttpSession session = login("alice");
        MvcResult result = mvc.perform(put("/api/users/me").session(session).with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(body(Map.of("username", "renamed", "email", "new@example.test"))))
                .andExpect(status().isOk()).andExpect(jsonPath("$.id").value(userId)).andReturn();
        assertNoPassword(node(result));
        mvc.perform(get("/api/users/me").session(session)).andExpect(jsonPath("$.username").value("renamed"));
        assertThat(users.findById(userId).getRole().name()).isEqualTo("USER");
    }

    @Test
    void cannotModifyAnotherProfileByUrlOrBody() throws Exception {
        register("alice", "alice@example.test");
        long bobId = register("bob", "bob@example.test").path("id").asLong();
        MockHttpSession session = login("alice");
        String update = body(Map.of("username", "changed", "email", "changed@example.test"));
        mvc.perform(put("/api/users/" + bobId).session(session).with(csrf())
                .contentType(MediaType.APPLICATION_JSON).content(update)).andExpect(status().isNotFound());
        mvc.perform(put("/api/users/me").session(session).with(csrf()).contentType(MediaType.APPLICATION_JSON)
                .content(body(Map.of("username", "changed", "email", "changed@example.test", "id", bobId))))
                .andExpect(status().isBadRequest());
        assertThat(users.findById(bobId).getUsername()).isEqualTo("bob");
    }

    @Test
    void authorCanCreateReadUpdateAndDeleteArticle() throws Exception {
        long owner = register("alice", "alice@example.test").path("id").asLong();
        MockHttpSession session = login("alice");
        JsonNode article = create(session, "Original", "Original content");
        long id = article.path("id").asLong();
        assertThat(article.path("userId").asLong()).isEqualTo(owner);
        mvc.perform(get("/api/articles/" + id).session(session)).andExpect(status().isOk());
        mvc.perform(put("/api/articles/" + id).session(session).with(csrf()).contentType(MediaType.APPLICATION_JSON)
                .content(articleBody("Updated", "Updated content")))
                .andExpect(status().isOk()).andExpect(jsonPath("$.title").value("Updated"));
        mvc.perform(delete("/api/articles/" + id).session(session).with(csrf())).andExpect(status().isNoContent());
        mvc.perform(get("/api/articles/" + id).session(session)).andExpect(status().isNotFound());
    }

    @Test
    void otherUsersCanReadAndSearchButCannotUpdateOrDelete() throws Exception {
        register("alice", "alice@example.test");
        register("bob", "bob@example.test");
        MockHttpSession alice = login("alice");
        long id = create(alice, "Visible article", "Shared content").path("id").asLong();
        MockHttpSession bob = login("bob");
        mvc.perform(get("/api/articles/" + id).session(bob)).andExpect(status().isOk());
        mvc.perform(get("/api/articles").session(bob)).andExpect(status().isOk()).andExpect(jsonPath("$.length()").value(1));
        mvc.perform(get("/api/articles/search").param("q", "Visible").session(bob))
                .andExpect(status().isOk()).andExpect(jsonPath("$[0].id").value(id));
        mvc.perform(put("/api/articles/" + id).session(bob).with(csrf()).contentType(MediaType.APPLICATION_JSON)
                .content(articleBody("Stolen", "content"))).andExpect(status().isForbidden());
        mvc.perform(delete("/api/articles/" + id).session(bob).with(csrf())).andExpect(status().isForbidden());
        mvc.perform(get("/api/articles/" + id).session(alice)).andExpect(jsonPath("$.title").value("Visible article"));
    }

    @Test
    void adminRoleDoesNotBypassOwnership() throws Exception {
        register("alice", "alice@example.test");
        register("admin", "admin@example.test");
        jdbc.update("UPDATE app_users SET role = ? WHERE username = ?", "ADMIN", "admin");
        long id = create(login("alice"), "Owned", "content").path("id").asLong();
        MockHttpSession admin = login("admin");
        mvc.perform(get("/api/users/me").session(admin)).andExpect(jsonPath("$.role").value("ADMIN"));
        mvc.perform(delete("/api/articles/" + id).session(admin).with(csrf())).andExpect(status().isForbidden());
        mvc.perform(put("/api/articles/" + id).session(admin).with(csrf()).contentType(MediaType.APPLICATION_JSON)
                .content(articleBody("Changed", "content"))).andExpect(status().isForbidden());
    }

    @Test
    void clientCannotAssignOrTransferArticleOwner() throws Exception {
        register("alice", "alice@example.test");
        long bob = register("bob", "bob@example.test").path("id").asLong();
        MockHttpSession alice = login("alice");
        String forged = body(Map.of("title", "forged", "content", "content", "userId", bob));
        mvc.perform(post("/api/articles").session(alice).with(csrf()).contentType(MediaType.APPLICATION_JSON)
                .content(forged)).andExpect(status().isBadRequest());
        long id = create(alice, "Original", "content").path("id").asLong();
        mvc.perform(put("/api/articles/" + id).session(alice).with(csrf()).contentType(MediaType.APPLICATION_JSON)
                .content(forged)).andExpect(status().isBadRequest());
        assertThat(jdbc.queryForObject("SELECT user_id FROM articles WHERE id = ?", Long.class, id)).isNotEqualTo(bob);
    }

    @Test
    void changingUrlIdCannotModifyAnotherOwnersArticle() throws Exception {
        register("alice", "alice@example.test");
        register("bob", "bob@example.test");
        MockHttpSession alice = login("alice");
        long own = create(alice, "Alice article", "content").path("id").asLong();
        long other = create(login("bob"), "Bob article", "content").path("id").asLong();
        mvc.perform(put("/api/articles/" + other).session(alice).with(csrf()).contentType(MediaType.APPLICATION_JSON)
                .content(articleBody("Changed", "content"))).andExpect(status().isForbidden());
        mvc.perform(delete("/api/articles/" + other).session(alice).with(csrf())).andExpect(status().isForbidden());
        mvc.perform(get("/api/articles/" + own).session(alice)).andExpect(jsonPath("$.title").value("Alice article"));
        mvc.perform(get("/api/articles/" + other).session(alice)).andExpect(jsonPath("$.title").value("Bob article"));
    }

    @Test
    void sqlSearchInputRemainsLiteralAndDoesNotChangeQuerySemantics() throws Exception {
        register("alice", "alice@example.test");
        MockHttpSession session = login("alice");
        String input = "' OR 1=1 --";
        long matching = create(session, input, "literal search sample").path("id").asLong();
        create(session, "Unrelated", "unrelated content");
        mvc.perform(get("/api/articles/search").session(session).param("q", input))
                .andExpect(status().isOk()).andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].id").value(matching));
        mvc.perform(get("/api/articles/search").session(session).param("q", "'; DROP TABLE articles; --"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.length()").value(0));
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM articles", Integer.class)).isEqualTo(2);
    }

    @Test
    void likeWildcardsAreLiteralAndPagingIsBounded() throws Exception {
        register("alice", "alice@example.test");
        MockHttpSession session = login("alice");
        create(session, "100%_! literal", "sample");
        create(session, "unrelated", "sample");
        for (String query : List.of("%", "_", "!")) {
            mvc.perform(get("/api/articles/search").session(session).param("q", query))
                    .andExpect(status().isOk()).andExpect(jsonPath("$.length()").value(1));
        }
        mvc.perform(get("/api/articles").session(session).param("size", "1"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.length()").value(1));
        mvc.perform(get("/api/articles").session(session).param("size", "101"))
                .andExpect(status().isBadRequest());
        mvc.perform(get("/api/articles/search").session(session).param("q", " "))
                .andExpect(status().isBadRequest());
    }

    @Test
    void invalidArticleAndMalformedJsonReturn400WithoutInternals() throws Exception {
        register("alice", "alice@example.test");
        MockHttpSession session = login("alice");
        for (String input : List.of(articleBody("", "content"), articleBody("title", ""),
                articleBody("x".repeat(201), "content"), articleBody("title", "界".repeat(20001)), "{broken")) {
            mvc.perform(post("/api/articles").session(session).with(csrf()).contentType(MediaType.APPLICATION_JSON)
                    .content(input)).andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.message").value("Invalid request"))
                    .andExpect(jsonPath("$.trace").doesNotExist());
        }
        mvc.perform(get("/api/articles/not-a-number").session(session)).andExpect(status().isBadRequest());
        mvc.perform(get("/api/articles/-1").session(session)).andExpect(status().isBadRequest());
    }

    @Test
    void healthExposesStatusWithoutDatabaseDetails() throws Exception {
        mvc.perform(get("/actuator/health")).andExpect(status().isOk()).andExpect(jsonPath("$.status").value("UP"))
                .andExpect(jsonPath("$.components").doesNotExist());
        mvc.perform(get("/actuator/env")).andExpect(status().isUnauthorized());
    }

    private JsonNode register(String name, String email) throws Exception {
        return node(mvc.perform(post("/api/auth/register").with(csrf()).contentType(MediaType.APPLICATION_JSON)
                .content(body(Map.of("username", name, "email", email, "password", password))))
                .andExpect(status().isCreated()).andReturn());
    }

    private MockHttpSession login(String name) throws Exception {
        MvcResult result = mvc.perform(post("/api/auth/login").with(csrf()).param("username", name).param("password", password))
                .andExpect(status().isOk()).andReturn();
        return (MockHttpSession) result.getRequest().getSession(false);
    }

    private JsonNode create(MockHttpSession session, String title, String content) throws Exception {
        return node(mvc.perform(post("/api/articles").session(session).with(csrf()).contentType(MediaType.APPLICATION_JSON)
                .content(articleBody(title, content))).andExpect(status().isCreated()).andReturn());
    }

    private String articleBody(String title, String content) {
        return body(Map.of("title", title, "content", content));
    }

    private String body(Object value) {
        return json.writeValueAsString(value);
    }

    private JsonNode node(MvcResult result) throws Exception {
        return json.readTree(result.getResponse().getContentAsString());
    }

    private void assertNoPassword(JsonNode response) {
        assertThat(response.has("password")).isFalse();
        assertThat(response.has("passwordHash")).isFalse();
        assertThat(response.has("password_hash")).isFalse();
        assertThat(response.toString()).doesNotContain(password, "$2a$", "$2b$");
    }
}
