package co.edu.corhuila.synkro.auth.app;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.security.KeyPair;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * register is an operation of a human ADMIN: who is calling, what that caller may do, and what the
 * database holds afterwards, over real HTTP against the real PostgreSQL schema.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@EnabledIfEnvironmentVariable(named = DatabaseTestSupport.URL_VARIABLE, matches = ".+")
class RegisterAdminOnlyHttpIntegrationTest {

    private static final KeyPair KEYS = TestKeys.generate(2048);
    private static final KeyPair OTHER_KEYS = TestKeys.generate(2048);
    private static final String PASSWORD = "pw-" + UUID.randomUUID();

    @DynamicPropertySource
    static void configuration(DynamicPropertyRegistry registry) throws Exception {
        DatabaseTestSupport.registerSigningKey(registry, KEYS, "register-admin-only-http-test");
        DatabaseTestSupport.registerDatasource(registry);
    }

    @LocalServerPort
    int port;

    private final TestRestTemplate http = new TestRestTemplate();
    private final ObjectMapper json = new ObjectMapper();
    private final JdbcTemplate jdbc = DatabaseTestSupport.jdbc();

    // ── helpers ──────────────────────────────────────────────────────

    private static String newKey() {
        return "it-key-" + UUID.randomUUID();
    }

    private static Map<String, Object> request(String email, String role) {
        Map<String, Object> body = new HashMap<>();
        body.put("name", "Ana Perez");
        body.put("email", email);
        body.put("password", PASSWORD);
        body.put("role", role);
        return body;
    }

    private ResponseEntity<String> register(Map<String, Object> body, String key, String authorization, String... headerPairs) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("Idempotency-Key", key);
        for (int i = 0; i < headerPairs.length; i += 2) {
            headers.set(headerPairs[i], headerPairs[i + 1]);
        }
        if (authorization != null) {
            headers.set("Authorization", authorization);
        }
        return http.exchange("http://localhost:" + port + "/api/v1/auth/register", HttpMethod.POST,
            new HttpEntity<>(body, headers), String.class);
    }

    private static String bearer(String token) {
        return "Bearer " + token;
    }

    private static String tokenFor(KeyPair keys, String subject, String role, Instant expiresAt) {
        return Jwts.builder()
            .subject(subject)
            .claim("roles", List.of(role))
            .claim("permissions", List.of())
            .expiration(Date.from(expiresAt))
            .signWith(keys.getPrivate(), Jwts.SIG.RS256)
            .compact();
    }

    private String seededUser(String role) {
        return DatabaseTestSupport.insertUser(jdbc, DatabaseTestSupport.uniqueEmail(), PASSWORD, role, true);
    }

    private JsonNode body(ResponseEntity<String> response) throws Exception {
        return json.readTree(response.getBody());
    }

    private int count(String table) {
        return jdbc.queryForObject("SELECT count(*) FROM auth_schema." + table, Integer.class);
    }

    /** Every table that registering writes. */
    private record Rows(int users, int keys, int audits) {}

    private Rows rows() {
        return new Rows(count("system_user"), count("idempotency_key"), count("user_creation_audit"));
    }

    // ── AUTH-REG-02: authentication (401) ────────────────────────────────────────────────

    @Test
    @Tag("AUTH-REG-02")
    void unauthenticated_aMissingAuthorizationHeader_is401_andWritesNothing() throws Exception {
        Rows before = rows();

        ResponseEntity<String> response = register(request(DatabaseTestSupport.uniqueEmail(), "SALESPERSON"), newKey(), null);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(body(response).get("error").asText()).isEqualTo("UNAUTHORIZED");
        assertThat(rows()).isEqualTo(before);
    }

    @Test
    @Tag("AUTH-REG-02")
    void unauthenticated_aMalformedToken_is401_andWritesNothing() {
        Rows before = rows();

        ResponseEntity<String> response = register(request(DatabaseTestSupport.uniqueEmail(), "SALESPERSON"), newKey(), bearer("not.a.jwt"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(rows()).isEqualTo(before);
    }

    @Test
    @Tag("AUTH-REG-02")
    void unauthenticated_anExpiredToken_is401_andWritesNothing() {
        String expired = tokenFor(KEYS, seededUser("ADMIN"), "ADMIN", Instant.now().minusSeconds(3600));
        Rows before = rows();

        ResponseEntity<String> response = register(request(DatabaseTestSupport.uniqueEmail(), "SALESPERSON"), newKey(), bearer(expired));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(rows()).isEqualTo(before);
    }

    @Test
    @Tag("AUTH-REG-02")
    void unauthenticated_aTokenWithAnInvalidSignature_is401_andWritesNothing() {
        String forged = tokenFor(OTHER_KEYS, seededUser("ADMIN"), "ADMIN", Instant.now().plusSeconds(300));
        Rows before = rows();

        ResponseEntity<String> response = register(request(DatabaseTestSupport.uniqueEmail(), "SALESPERSON"), newKey(), bearer(forged));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(rows()).isEqualTo(before);
    }

    // ── AUTH-REG-02: authorization (403) ───────────────────────────────────────────────────────────

    private String tokenOf(String role) {
        String subject = "SERVICE".equals(role) ? "synkro-workflow" : seededUser(role);
        return bearer(tokenFor(KEYS, subject, role, Instant.now().plusSeconds(300)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"SALESPERSON", "INVENTORY"})
    @Tag("AUTH-REG-02")
    void forbidden_aValidTokenForAnotherHumanRole_is403_andWritesNothing(String role) throws Exception {
        String token = tokenOf(role);
        String email = DatabaseTestSupport.uniqueEmail();
        Rows before = rows();

        ResponseEntity<String> response = register(request(email, "SALESPERSON"), newKey(), token);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(body(response).get("error").asText()).isEqualTo("FORBIDDEN");
        assertThat(response.getBody()).doesNotContain(email).doesNotContain("userId");
        assertThat(rows()).isEqualTo(before);
    }

    @Test
    @Tag("AUTH-REG-02")
    void forbidden_aServiceToken_is403_evenWithAKeyThatAlreadyCreatedAUser_andTheUserIsNotDisclosed() throws Exception {
        String email = DatabaseTestSupport.uniqueEmail();
        String key = newKey();
        ResponseEntity<String> created = register(request(email, "SALESPERSON"), key, tokenOf("ADMIN"));
        assertThat(created.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        String userId = body(created).get("userId").asText();
        Rows before = rows();

        ResponseEntity<String> replay = register(request(email, "SALESPERSON"), key, tokenOf("SERVICE"));

        assertThat(replay.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(replay.getBody()).doesNotContain(email).doesNotContain(userId);
        assertThat(replay.getHeaders().getLocation()).isNull();
        assertThat(rows()).isEqualTo(before);
    }

    @Test
    @Tag("AUTH-REG-02")
    void authorized_anAdminToken_proceedsPastAuthorization() {
        ResponseEntity<String> response = register(request(DatabaseTestSupport.uniqueEmail(), "SALESPERSON"), newKey(), tokenOf("ADMIN"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
    }

    // ── AUTH-REG-03/04 over HTTP: what the database holds ────────────

    private String adminBearer(String adminId) {
        return bearer(tokenFor(KEYS, adminId, "ADMIN", Instant.now().plusSeconds(300)));
    }

    private int auditRowsOf(String userId) {
        return jdbc.queryForObject("SELECT count(*) FROM auth_schema.user_creation_audit WHERE created_user_id = ?::uuid",
            Integer.class, userId);
    }

    @Test
    @Tag("AUTH-REG-04")
    void atomicity_theFirstCreate_is201_andLeavesOneRowInEachOfTheThreeTables_attributedToTheAdmin() throws Exception {
        String adminId = seededUser("ADMIN");
        String correlation = "corr-" + UUID.randomUUID();
        Rows before = rows();

        ResponseEntity<String> response = register(request(DatabaseTestSupport.uniqueEmail(), "INVENTORY"), newKey(),
            adminBearer(adminId), "X-Correlation-Id", correlation);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        String userId = body(response).get("userId").asText();
        assertThat(response.getHeaders().getLocation()).hasToString("/api/v1/auth/users/" + userId);
        assertThat(rows()).isEqualTo(new Rows(before.users() + 1, before.keys() + 1, before.audits() + 1));
        Map<String, Object> audit = jdbc.queryForMap(
            "SELECT operation, actor_kind, actor_user_id::text AS actor, operator_identity, outcome, correlation_id, occurred_at "
                + "FROM auth_schema.user_creation_audit WHERE created_user_id = ?::uuid", userId);
        assertThat(audit.get("operation")).isEqualTo("USER_REGISTERED");
        assertThat(audit.get("actor_kind")).isEqualTo("ADMIN");
        assertThat(audit.get("actor")).isEqualTo(adminId);
        assertThat(audit.get("operator_identity")).isNull();
        assertThat(audit.get("outcome")).isEqualTo("SUCCESS");
        assertThat(audit.get("correlation_id")).isEqualTo(correlation);
        assertThat(((java.sql.Timestamp) audit.get("occurred_at")).toInstant())
            .isBetween(Instant.now().minusSeconds(60), Instant.now().plusSeconds(5));
    }

    @Test
    @Tag("AUTH-REG-03")
    void replay_replayingTheSameAuthorizedRequestAndKey_is200WithTheSameUser_andTheAuditCountStaysAtOne() throws Exception {
        String token = adminBearer(seededUser("ADMIN"));
        String email = DatabaseTestSupport.uniqueEmail();
        String key = newKey();
        ResponseEntity<String> first = register(request(email, "INVENTORY"), key, token);
        String userId = body(first).get("userId").asText();
        Rows afterFirst = rows();

        for (int replay = 0; replay < 3; replay++) {
            ResponseEntity<String> again = register(request(email, "INVENTORY"), key, token);
            assertThat(again.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(body(again).get("userId").asText()).isEqualTo(userId);
        }

        assertThat(rows()).isEqualTo(afterFirst);
        assertThat(auditRowsOf(userId)).isEqualTo(1);
    }

    @Test
    @Tag("AUTH-REG-03")
    void duplicateEmail_aDuplicateEmailWithANewKey_is422BusinessRuleViolation_andWritesNoAuditRow() throws Exception {
        String token = adminBearer(seededUser("ADMIN"));
        String email = DatabaseTestSupport.uniqueEmail();
        register(request(email, "INVENTORY"), newKey(), token);
        Rows before = rows();

        ResponseEntity<String> response = register(request(email, "SALESPERSON"), newKey(), token);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNPROCESSABLE_ENTITY);
        assertThat(body(response).get("error").asText()).isEqualTo("BUSINESS_RULE_VIOLATION");
        assertThat(rows()).isEqualTo(before);
    }

    // ── the ADMIN named by the token ─────────────────────────────────

    @Test
    @Tag("AUTH-REG-02")
    void subject_aHumanAdminTokenWithASubjectThatIsNotAUuid_is401_andWritesNothing() throws Exception {
        String malformedSubject = bearer(tokenFor(KEYS, "not-a-uuid", "ADMIN", Instant.now().plusSeconds(300)));
        Rows before = rows();

        ResponseEntity<String> response = register(request(DatabaseTestSupport.uniqueEmail(), "INVENTORY"), newKey(), malformedSubject);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(body(response).get("error").asText()).isEqualTo("UNAUTHORIZED");
        assertThat(rows()).isEqualTo(before);
    }

    @Test
    @Tag("AUTH-REG-02")
    void subject_anAdminTokenWithAWellFormedUuidThatDoesNotExist_is403_andWritesNothing() throws Exception {
        String ghostAdmin = adminBearer(UUID.randomUUID().toString());
        String email = DatabaseTestSupport.uniqueEmail();
        String key = newKey();
        Rows before = rows();

        ResponseEntity<String> response = register(request(email, "INVENTORY"), key, ghostAdmin);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(body(response).get("error").asText()).isEqualTo("FORBIDDEN");
        assertThat(response.getBody()).doesNotContain(email).doesNotContain("exist").doesNotContain("userId");
        assertThat(rows()).isEqualTo(before);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM auth_schema.idempotency_key WHERE key = ?", Integer.class, key)).isZero();
    }

    @Test
    @Tag("AUTH-REG-02")
    void subject_aMissingAdminReplayingAKeyThatAlreadyCreatedAUser_is403_andTheUserIsNotDisclosed() throws Exception {
        String email = DatabaseTestSupport.uniqueEmail();
        String key = newKey();
        ResponseEntity<String> created = register(request(email, "INVENTORY"), key, adminBearer(seededUser("ADMIN")));
        String userId = body(created).get("userId").asText();
        Rows before = rows();

        ResponseEntity<String> replay = register(request(email, "INVENTORY"), key, adminBearer(UUID.randomUUID().toString()));

        assertThat(replay.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(replay.getBody()).doesNotContain(email).doesNotContain(userId);
        assertThat(replay.getHeaders().getLocation()).isNull();
        assertThat(rows()).isEqualTo(before);
    }

    @Test
    @Tag("AUTH-REG-02")
    void subject_aServiceTokenWithAServiceNameAsSubject_isAuthenticated_andForbiddenToRegister() throws Exception {
        Rows before = rows();

        ResponseEntity<String> response = register(request(DatabaseTestSupport.uniqueEmail(), "INVENTORY"), newKey(), tokenOf("SERVICE"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(rows()).isEqualTo(before);
    }

    @Test
    @Tag("AUTH-REG-03")
    void serviceAsTheRequestedRole_is400_andWritesNothing() throws Exception {
        Rows before = rows();

        ResponseEntity<String> response = register(request(DatabaseTestSupport.uniqueEmail(), "SERVICE"), newKey(), adminBearer(seededUser("ADMIN")));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(body(response).get("error").asText()).isEqualTo("VALIDATION_ERROR");
        assertThat(rows().keys()).isEqualTo(before.keys());
        assertThat(rows().audits()).isEqualTo(before.audits());
    }

    // ── scope of the UUID rule: every protected route, never the public ones ──

    private String tokenWithRoles(String subject, List<String> roles) {
        return Jwts.builder().subject(subject).claim("roles", roles).claim("permissions", List.of())
            .expiration(Date.from(Instant.now().plusSeconds(300))).signWith(KEYS.getPrivate(), Jwts.SIG.RS256).compact();
    }

    private ResponseEntity<String> send(HttpMethod method, String path, Object body, String authorization) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        if (authorization != null) {
            headers.set("Authorization", authorization);
        }
        return http.exchange("http://localhost:" + port + path, method, new HttpEntity<>(body, headers), String.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"1-1-1-1-1", "00000000000000000000000000000001", "{00000000-0000-0000-0000-000000000001}", "user-42", ""})
    @Tag("AUTH-REG-02")
    void subject_aHumanSubjectThatIsNotInCanonicalUuidForm_is401_andWritesNothing(String subject) {
        // "1-1-1-1-1" and the undashed form are accepted by java.util.UUID.fromString; only the canonical form is an identity here
        Rows before = rows();
        String token = tokenWithRoles(subject.isEmpty() ? " " : subject, List.of("ADMIN"));

        ResponseEntity<String> response = register(request(DatabaseTestSupport.uniqueEmail(), "INVENTORY"), newKey(), bearer(token));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(rows()).isEqualTo(before);
    }

    @Test
    @Tag("AUTH-REG-02")
    void subject_aTokenCarryingBothAdminAndService_isForbiddenToRegister_andWritesNothing() {
        Rows before = rows();
        String token = tokenWithRoles("synkro-workflow", List.of("ADMIN", "SERVICE"));

        ResponseEntity<String> response = register(request(DatabaseTestSupport.uniqueEmail(), "INVENTORY"), newKey(), bearer(token));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(rows()).isEqualTo(before);
    }

    @Test
    @Tag("AUTH-REG-02")
    void subject_aMalformedHumanSubject_is401OnAProtectedLookup_andAValidOneStillReadsTheUser() throws Exception {
        String adminId = seededUser("ADMIN");

        assertThat(send(HttpMethod.GET, "/api/v1/auth/users/" + adminId, null, bearer(tokenWithRoles("user-42", List.of("ADMIN")))).getStatusCode())
            .isEqualTo(HttpStatus.UNAUTHORIZED);
        ResponseEntity<String> valid = send(HttpMethod.GET, "/api/v1/auth/users/" + adminId, null, adminBearer(adminId));
        assertThat(valid.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(body(valid).get("userId").asText()).isEqualTo(adminId);
    }

    @Test
    @Tag("AUTH-REG-02")
    void subject_aBadSubjectOnTheAuthorizationHeader_doesNotBlockLoginOrRefresh() throws Exception {
        String email = DatabaseTestSupport.uniqueEmail();
        DatabaseTestSupport.insertUser(jdbc, email, PASSWORD, "INVENTORY", true);
        String badHeader = bearer(tokenWithRoles("user-42", List.of("ADMIN")));

        ResponseEntity<String> login = send(HttpMethod.POST, "/api/v1/auth/login", Map.of("email", email, "password", PASSWORD), badHeader);
        assertThat(login.getStatusCode()).isEqualTo(HttpStatus.OK);
        String refreshToken = body(login).get("refreshToken").asText();

        ResponseEntity<String> refresh = send(HttpMethod.POST, "/api/v1/auth/refresh", Map.of("refreshToken", refreshToken), badHeader);
        assertThat(refresh.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    // ── AUTH-REG-01: an ADMIN creates each permitted human role ──────

    @ParameterizedTest
    @ValueSource(strings = {"ADMIN", "SALESPERSON", "INVENTORY"})
    @Tag("AUTH-REG-01")
    void anAdminCreatesEachPermittedHumanRole_attributedToTheTokensSubject_withAHashedPassword(String role) throws Exception {
        String adminId = seededUser("ADMIN");
        String email = DatabaseTestSupport.uniqueEmail();

        ResponseEntity<String> response = register(request(email, role), newKey(), adminBearer(adminId));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        String userId = body(response).get("userId").asText();
        assertThat(body(response).get("role").asText()).isEqualTo(role);
        String storedHash = jdbc.queryForObject("SELECT password_hash FROM auth_schema.system_user WHERE user_id = ?::uuid", String.class, userId);
        assertThat(storedHash).startsWith("$2").isNotEqualTo(PASSWORD);
        assertThat(response.getBody()).doesNotContain(PASSWORD).doesNotContain(storedHash);
        assertThat(jdbc.queryForObject("SELECT actor_user_id::text FROM auth_schema.user_creation_audit WHERE created_user_id = ?::uuid",
            String.class, userId)).isEqualTo(adminId);
    }

    @Test
    @Tag("AUTH-REG-01")
    void theCreatorIsTheTokensSubject_notAnyFieldOfTheBodyOrAUserHeader() throws Exception {
        String adminId = seededUser("ADMIN");
        String someoneElse = seededUser("ADMIN");
        Map<String, Object> body = request(DatabaseTestSupport.uniqueEmail(), "INVENTORY");
        body.put("createdBy", someoneElse);
        body.put("actorUserId", someoneElse);

        ResponseEntity<String> response = register(body, newKey(), adminBearer(adminId),
            "X-User-Id", someoneElse, "X-User-Role", "ADMIN");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(jdbc.queryForObject("SELECT actor_user_id::text FROM auth_schema.user_creation_audit WHERE created_user_id = ?::uuid",
            String.class, body(response).get("userId").asText())).isEqualTo(adminId);
    }

    @Test
    @Tag("AUTH-REG-04")
    void atomicity_concurrentAuthorizedRequestsWithTheSameKey_createOneUser_andWriteOneAuditRow() throws Exception {
        String token = adminBearer(seededUser("ADMIN"));
        for (int round = 0; round < 5; round++) {
            String email = DatabaseTestSupport.uniqueEmail();
            String key = newKey();
            Rows before = rows();

            List<ResponseEntity<String>> responses = together(
                () -> register(request(email, "INVENTORY"), key, token),
                () -> register(request(email, "INVENTORY"), key, token),
                () -> register(request(email, "INVENTORY"), key, token));

            assertThat(responses).extracting(r -> r.getStatusCode().value()).containsExactlyInAnyOrder(201, 200, 200);
            String userId = body(responses.get(0)).get("userId").asText();
            assertThat(responses).allSatisfy(r -> assertThat(body(r).get("userId").asText()).isEqualTo(userId));
            assertThat(rows()).isEqualTo(new Rows(before.users() + 1, before.keys() + 1, before.audits() + 1));
            assertThat(auditRowsOf(userId)).isEqualTo(1);
        }
    }

    @SafeVarargs
    private <T> List<T> together(java.util.concurrent.Callable<T>... tasks) throws Exception {
        java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newFixedThreadPool(tasks.length);
        java.util.concurrent.CountDownLatch ready = new java.util.concurrent.CountDownLatch(tasks.length);
        java.util.concurrent.CountDownLatch go = new java.util.concurrent.CountDownLatch(1);
        List<java.util.concurrent.Future<T>> futures = new java.util.ArrayList<>();
        for (java.util.concurrent.Callable<T> task : tasks) {
            futures.add(pool.submit(() -> {
                ready.countDown();
                go.await();
                return task.call();
            }));
        }
        ready.await();
        go.countDown();
        List<T> results = new java.util.ArrayList<>();
        for (java.util.concurrent.Future<T> future : futures) {
            results.add(future.get());
        }
        pool.shutdown();
        return results;
    }
}
