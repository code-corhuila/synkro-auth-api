package co.edu.corhuila.synkro.auth.app;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import co.edu.corhuila.synkro.auth.application.port.out.PasswordResetStore;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
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
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * An ADMIN resets a user's password over real HTTP and real PostgreSQL, with no fakes: who may, who may not, what it does
 * to the target's login, refresh tokens and audit, how a retry with the same key behaves, and that nothing secret is
 * logged (HU-AUTH-19, ADR-021). The only test double is a decorator that, for chosen keys only, makes the store fail
 * before the commit, after it, or while writing a corrupt audit row.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import(ResetPasswordHttpIntegrationTest.FaultInjection.class)
@EnabledIfEnvironmentVariable(named = DatabaseTestSupport.URL_VARIABLE, matches = ".+")
class ResetPasswordHttpIntegrationTest {

    private static final KeyPair KEYS = TestKeys.generate(2048);
    private static final String OLD_PASSWORD = "old-" + UUID.randomUUID();
    private static final String NEW_PASSWORD = "new-" + UUID.randomUUID();
    // Fewer than 8 characters, unique, so its absence from every log line means something.
    private static final String SHORT_PASSWORD = "p@" + UUID.randomUUID().toString().substring(0, 4);
    private static final String SECURITY_LOGGER = "synkro.auth.security";

    enum Fault { BEFORE_COMMIT, AFTER_COMMIT, CORRUPT_AUDIT }

    /** Faults by idempotency key, so a test fails only its own request and everything else runs for real. */
    static final Map<String, Fault> FAULTS = new ConcurrentHashMap<>();

    @TestConfiguration
    static class FaultInjection {
        @Bean
        static BeanPostProcessor failTheStoreForChosenKeys() {
            return new BeanPostProcessor() {
                @Override
                public Object postProcessAfterInitialization(Object bean, String beanName) {
                    if (!(bean instanceof PasswordResetStore real)) {
                        return bean;
                    }
                    return new PasswordResetStore() {
                        @Override
                        public Optional<Recorded> findByActorAndKey(String actorUserId, String idempotencyKey) {
                            return real.findByActorAndKey(actorUserId, idempotencyKey);
                        }

                        @Override
                        public Outcome resetPasswordWithAudit(String key, String targetUserId, String hash, ResetAttribution a) {
                            Fault fault = FAULTS.get(key);
                            if (fault == Fault.BEFORE_COMMIT) {
                                throw new IllegalStateException("injected failure before the commit");
                            }
                            if (fault == Fault.CORRUPT_AUDIT) {
                                return real.resetPasswordWithAudit(key, targetUserId, hash, new ResetAttribution(
                                    a.auditId(), UUID.randomUUID().toString(), a.occurredAt(), a.correlationId()));
                            }
                            Outcome outcome = real.resetPasswordWithAudit(key, targetUserId, hash, a);
                            if (fault == Fault.AFTER_COMMIT) {
                                throw new IllegalStateException("injected failure after the commit: the response is lost");
                            }
                            return outcome;
                        }
                    };
                }
            };
        }
    }

    @DynamicPropertySource
    static void configuration(DynamicPropertyRegistry registry) throws Exception {
        DatabaseTestSupport.registerSigningKey(registry, KEYS, "reset-password-http-it");
        DatabaseTestSupport.registerDatasource(registry);
    }

    @LocalServerPort
    int port;

    private final TestRestTemplate http = new TestRestTemplate();
    private final ObjectMapper json = new ObjectMapper();
    private final JdbcTemplate jdbc = DatabaseTestSupport.jdbc();
    private final ListAppender<ILoggingEvent> everything = new ListAppender<>();
    private Logger root;

    @BeforeEach
    void captureLogs() {
        root = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
        everything.start();
        root.addAppender(everything);
    }

    @AfterEach
    void releaseLogs() {
        root.detachAppender(everything);
        FAULTS.clear();
    }

    // ── helpers ──────────────────────────────────────────────────────

    private record Account(String userId, String email, String accessToken, String refreshToken) {}

    private static String newKey() {
        return "it-reset-" + UUID.randomUUID();
    }

    private ResponseEntity<String> post(String path, Object body, String bearer, Map<String, String> extraHeaders) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        if (bearer != null) {
            headers.setBearerAuth(bearer);
        }
        extraHeaders.forEach(headers::set);
        return http.postForEntity("http://localhost:" + port + path, new HttpEntity<>(body, headers), String.class);
    }

    private ResponseEntity<String> login(String email, String password) {
        return post("/api/v1/auth/login", Map.of("email", email, "password", password), null, Map.of());
    }

    private ResponseEntity<String> refresh(String refreshToken) {
        return post("/api/v1/auth/refresh", Map.of("refreshToken", refreshToken), null, Map.of());
    }

    private JsonNode body(ResponseEntity<String> response) throws Exception {
        return json.readTree(response.getBody());
    }

    private Account newAccount(String role, boolean active) throws Exception {
        String email = DatabaseTestSupport.uniqueEmail();
        String userId = DatabaseTestSupport.insertUser(jdbc, email, OLD_PASSWORD, role, active);
        if (!active) {
            return new Account(userId, email, null, null);
        }
        JsonNode pair = body(login(email, OLD_PASSWORD));
        return new Account(userId, email, pair.get("accessToken").asText(), pair.get("refreshToken").asText());
    }

    private static Map<String, Object> passwordBody(String password) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("newPassword", password);
        body.put("confirmPassword", password);
        return body;
    }

    private ResponseEntity<String> reset(Account actor, String targetId, String key, Object body, String correlationId) {
        Map<String, String> headers = new LinkedHashMap<>();
        if (key != null) {
            headers.put("Idempotency-Key", key);
        }
        headers.put("X-Correlation-Id", correlationId);
        return post("/api/v1/auth/users/" + targetId + "/password-reset", body, actor == null ? null : actor.accessToken(), headers);
    }

    private ResponseEntity<String> reset(Account actor, String targetId, String key, String password) {
        return reset(actor, targetId, key, passwordBody(password), "corr-" + UUID.randomUUID());
    }

    private static String serviceToken() {
        return Jwts.builder().subject("synkro-workflow").claim("roles", List.of("SERVICE")).claim("permissions", List.of())
            .expiration(Date.from(Instant.now().plusSeconds(300))).signWith(KEYS.getPrivate(), Jwts.SIG.RS256).compact();
    }

    private int count(String sql, Object... args) {
        return jdbc.queryForObject(sql, Integer.class, args);
    }

    private int resetAudits(String targetId) {
        return count("SELECT count(*) FROM auth_schema.password_reset_audit WHERE target_user_id = ?::uuid", targetId);
    }

    private int totalResetAudits() {
        return count("SELECT count(*) FROM auth_schema.password_reset_audit");
    }

    private int activeRefreshRows(String userId) {
        return count("SELECT count(*) FROM auth_schema.refresh_token WHERE user_id = ?::uuid AND active", userId);
    }

    private HttpStatus status(ResponseEntity<String> response) {
        return HttpStatus.valueOf(response.getStatusCode().value());
    }

    private String allLoggedText() {
        StringBuilder text = new StringBuilder();
        for (ILoggingEvent event : List.copyOf(everything.list)) {
            text.append(event.getFormattedMessage()).append('\n');
            if (event.getThrowableProxy() != null) {
                text.append(event.getThrowableProxy().getMessage()).append('\n');
            }
        }
        return text.toString();
    }

    private List<ILoggingEvent> securityEventsOf(String correlationId) {
        return everything.list.stream().filter(e -> e.getLoggerName().equals(SECURITY_LOGGER))
            .filter(e -> e.getFormattedMessage().contains(correlationId)).toList();
    }

    // ── the happy path and its effects ───────────────────────────────

    @Test
    @Tag("AUTH-RESET-08")
    void anAdminResetsASalesperson_theOldPasswordIsRejected_theNewOneLogsIn_andOthersAreUnchanged() throws Exception {
        Account admin = newAccount("ADMIN", true);
        Account target = newAccount("SALESPERSON", true);
        Account bystander = newAccount("SALESPERSON", true);

        ResponseEntity<String> response = reset(admin, target.userId(), newKey(), NEW_PASSWORD);

        assertThat(status(response)).isEqualTo(HttpStatus.OK);
        assertThat(body(response).get("userId").asText()).isEqualTo(target.userId());
        assertThat(status(login(target.email(), OLD_PASSWORD))).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(status(login(target.email(), NEW_PASSWORD))).isEqualTo(HttpStatus.OK);
        assertThat(status(login(bystander.email(), OLD_PASSWORD))).as("another user's password is untouched").isEqualTo(HttpStatus.OK);
        assertThat(status(login(admin.email(), OLD_PASSWORD))).as("the administrator's own password is untouched").isEqualTo(HttpStatus.OK);
    }

    @Test
    void anAdminResetsAnInventoryUser() throws Exception {
        Account admin = newAccount("ADMIN", true);
        Account target = newAccount("INVENTORY", true);

        assertThat(status(reset(admin, target.userId(), newKey(), NEW_PASSWORD))).isEqualTo(HttpStatus.OK);

        assertThat(status(login(target.email(), NEW_PASSWORD))).isEqualTo(HttpStatus.OK);
    }

    @Test
    @Tag("AUTH-RESET-09")
    void theTargetsRefreshTokensAreRevoked_anotherUsersAreNot_andTheIssuedAccessTokenIsNotClaimedRevoked() throws Exception {
        Account admin = newAccount("ADMIN", true);
        Account target = newAccount("SALESPERSON", true);
        Account bystander = newAccount("SALESPERSON", true);

        reset(admin, target.userId(), newKey(), NEW_PASSWORD);

        assertThat(status(refresh(target.refreshToken()))).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(status(refresh(bystander.refreshToken()))).isEqualTo(HttpStatus.OK);
        // ADR-017: an access token already issued is stateless and stays valid until it expires. It still authenticates
        // (a salesperson is then refused by role, 403, never by identity, 401).
        ResponseEntity<String> stillAuthenticates = http.exchange("http://localhost:" + port + "/api/v1/auth/users/" + target.userId(),
            HttpMethod.GET, new HttpEntity<>(bearerOnly(target.accessToken())), String.class);
        assertThat(status(stillAuthenticates)).isEqualTo(HttpStatus.FORBIDDEN);
    }

    private static HttpHeaders bearerOnly(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        return headers;
    }

    @Test
    @Tag("AUTH-RESET-10")
    void theAuditNamesTheActorAndTheTarget_andHoldsNoSecret() throws Exception {
        Account admin = newAccount("ADMIN", true);
        Account target = newAccount("SALESPERSON", true);
        String key = newKey();
        String correlation = "corr-audit-" + UUID.randomUUID();

        ResponseEntity<String> response = reset(admin, target.userId(), key, passwordBody(NEW_PASSWORD), correlation);

        assertThat(status(response)).isEqualTo(HttpStatus.OK);
        Map<String, Object> row = jdbc.queryForMap("SELECT operation, actor_user_id::text AS actor, target_user_id::text AS target, "
            + "outcome, correlation_id, row(a.*)::text AS everything FROM auth_schema.password_reset_audit a WHERE idempotency_key = ?", key);
        assertThat(row.get("operation")).isEqualTo("PASSWORD_RESET");
        assertThat(row.get("actor")).isEqualTo(admin.userId());
        assertThat(row.get("target")).isEqualTo(target.userId());
        assertThat(row.get("outcome")).isEqualTo("SUCCESS");
        assertThat(row.get("correlation_id")).isEqualTo(correlation);
        String newHash = jdbc.queryForObject("SELECT password_hash FROM auth_schema.system_user WHERE user_id = ?::uuid", String.class, target.userId());
        assertThat((String) row.get("everything")).doesNotContain(NEW_PASSWORD).doesNotContain(newHash).doesNotContain(OLD_PASSWORD);
    }

    // ── who may not ──────────────────────────────────────────────────

    @Test
    @Tag("AUTH-RESET-11")
    void anonymousAndInvalidCredentials_are401_andNothingChanges() throws Exception {
        Account target = newAccount("SALESPERSON", true);
        int audits = totalResetAudits();

        assertThat(status(reset(null, target.userId(), newKey(), NEW_PASSWORD))).isEqualTo(HttpStatus.UNAUTHORIZED);
        Account forged = new Account(null, null, "not.a.valid.jwt", null);
        assertThat(status(reset(forged, target.userId(), newKey(), NEW_PASSWORD))).isEqualTo(HttpStatus.UNAUTHORIZED);

        assertThat(status(login(target.email(), OLD_PASSWORD))).isEqualTo(HttpStatus.OK);
        assertThat(totalResetAudits()).isEqualTo(audits);
    }

    @Test
    @Tag("AUTH-RESET-11")
    void salespersonInventoryAndServiceCallers_are403_calledDirectly_andNothingChanges() throws Exception {
        Account target = newAccount("SALESPERSON", true);
        Account salesperson = newAccount("SALESPERSON", true);
        Account inventory = newAccount("INVENTORY", true);
        Account service = new Account(null, null, serviceToken(), null);
        int audits = totalResetAudits();
        int active = activeRefreshRows(target.userId());

        for (Account caller : List.of(salesperson, inventory, service)) {
            assertThat(status(reset(caller, target.userId(), newKey(), NEW_PASSWORD))).isEqualTo(HttpStatus.FORBIDDEN);
        }

        assertThat(status(login(target.email(), OLD_PASSWORD))).isEqualTo(HttpStatus.OK);
        assertThat(totalResetAudits()).isEqualTo(audits);
        assertThat(activeRefreshRows(target.userId())).isGreaterThanOrEqualTo(active);
    }

    @Test
    void aValidTokenOfAnAdminWhoseAccountWasDeactivated_is403() throws Exception {
        Account admin = newAccount("ADMIN", true);
        Account target = newAccount("SALESPERSON", true);
        jdbc.update("UPDATE auth_schema.system_user SET active = false WHERE user_id = ?::uuid", admin.userId());

        assertThat(status(reset(admin, target.userId(), newKey(), NEW_PASSWORD))).isEqualTo(HttpStatus.FORBIDDEN);

        assertThat(status(login(target.email(), OLD_PASSWORD))).isEqualTo(HttpStatus.OK);
    }

    // ── who may not be reset, and bad input ──────────────────────────

    @Test
    @Tag("AUTH-RESET-12")
    void refusals_changeNothing_andAreTheRightStatus() throws Exception {
        Account admin = newAccount("ADMIN", true);
        Account otherAdmin = newAccount("ADMIN", true);
        Account inactive = newAccount("SALESPERSON", false);
        Account target = newAccount("SALESPERSON", true);
        int audits = totalResetAudits();
        int active = activeRefreshRows(target.userId());

        assertThat(status(reset(admin, UUID.randomUUID().toString(), newKey(), NEW_PASSWORD))).as("unknown target").isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(status(reset(admin, otherAdmin.userId(), newKey(), NEW_PASSWORD))).as("another admin").isEqualTo(HttpStatus.UNPROCESSABLE_ENTITY);
        assertThat(status(reset(admin, admin.userId(), newKey(), NEW_PASSWORD))).as("themselves").isEqualTo(HttpStatus.UNPROCESSABLE_ENTITY);
        assertThat(status(reset(admin, inactive.userId(), newKey(), NEW_PASSWORD))).as("inactive").isEqualTo(HttpStatus.UNPROCESSABLE_ENTITY);
        assertThat(status(reset(admin, "not-a-uuid", newKey(), NEW_PASSWORD))).as("malformed id").isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(status(reset(admin, target.userId(), null, NEW_PASSWORD))).as("no key").isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(status(reset(admin, target.userId(), newKey(), "short"))).as("short password").isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(status(reset(admin, target.userId(), newKey(), "x".repeat(73)))).as("73 bytes").isEqualTo(HttpStatus.BAD_REQUEST);
        Map<String, Object> mismatch = Map.of("newPassword", NEW_PASSWORD, "confirmPassword", NEW_PASSWORD + "x");
        assertThat(status(reset(admin, target.userId(), newKey(), mismatch, "corr-x"))).as("mismatch").isEqualTo(HttpStatus.BAD_REQUEST);

        assertThat(totalResetAudits()).isEqualTo(audits);
        assertThat(activeRefreshRows(target.userId())).isEqualTo(active);
        assertThat(status(login(target.email(), OLD_PASSWORD))).isEqualTo(HttpStatus.OK);
        assertThat(status(login(otherAdmin.email(), OLD_PASSWORD))).isEqualTo(HttpStatus.OK);
        assertThat(status(login(admin.email(), OLD_PASSWORD))).isEqualTo(HttpStatus.OK);
    }

    // ── the key ──────────────────────────────────────────────────────

    @Test
    @Tag("AUTH-RESET-13")
    void theSameKeyAndRequest_answers200WithTheFirstResult_changesNothing_andKeepsASessionOpenedAfterTheReset() throws Exception {
        Account admin = newAccount("ADMIN", true);
        Account target = newAccount("SALESPERSON", true);
        String key = newKey();
        JsonNode first = body(reset(admin, target.userId(), key, NEW_PASSWORD));
        JsonNode newSession = body(login(target.email(), NEW_PASSWORD));
        String hashAfterFirst = jdbc.queryForObject("SELECT password_hash FROM auth_schema.system_user WHERE user_id = ?::uuid", String.class, target.userId());

        ResponseEntity<String> replay = reset(admin, target.userId(), key, NEW_PASSWORD);

        assertThat(status(replay)).isEqualTo(HttpStatus.OK);
        assertThat(body(replay)).isEqualTo(first);
        assertThat(resetAudits(target.userId())).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT password_hash FROM auth_schema.system_user WHERE user_id = ?::uuid", String.class, target.userId()))
            .isEqualTo(hashAfterFirst);
        assertThat(status(refresh(newSession.get("refreshToken").asText()))).as("the new session was not revoked by the replay").isEqualTo(HttpStatus.OK);
    }

    @Test
    @Tag("AUTH-RESET-13")
    void theSameKeyWithAnotherPasswordOrTarget_is422_andNothingChanges() throws Exception {
        Account admin = newAccount("ADMIN", true);
        Account target = newAccount("SALESPERSON", true);
        Account another = newAccount("INVENTORY", true);
        String key = newKey();
        reset(admin, target.userId(), key, NEW_PASSWORD);

        ResponseEntity<String> otherPassword = reset(admin, target.userId(), key, "a-different-passphrase");
        ResponseEntity<String> otherTarget = reset(admin, another.userId(), key, NEW_PASSWORD);

        assertThat(status(otherPassword)).isEqualTo(HttpStatus.UNPROCESSABLE_ENTITY);
        assertThat(status(otherTarget)).isEqualTo(HttpStatus.UNPROCESSABLE_ENTITY);
        assertThat(body(otherPassword).get("details").get(0).get("field").asText()).isEqualTo("Idempotency-Key");
        assertThat(otherPassword.getBody()).doesNotContain(target.userId()).doesNotContain(NEW_PASSWORD);
        assertThat(status(login(target.email(), NEW_PASSWORD))).isEqualTo(HttpStatus.OK);
        assertThat(status(login(another.email(), OLD_PASSWORD))).isEqualTo(HttpStatus.OK);
        assertThat(resetAudits(target.userId()) + resetAudits(another.userId())).isEqualTo(1);
    }

    @Test
    @Tag("AUTH-RESET-13")
    void aKeyUsedByAnotherAdmin_isUnknownToThisOne() throws Exception {
        Account admin = newAccount("ADMIN", true);
        Account otherAdmin = newAccount("ADMIN", true);
        Account first = newAccount("SALESPERSON", true);
        Account second = newAccount("INVENTORY", true);
        String key = newKey();
        reset(admin, first.userId(), key, NEW_PASSWORD);

        ResponseEntity<String> mine = reset(otherAdmin, second.userId(), key, "other-admins-passphrase");

        assertThat(status(mine)).as("the key means nothing to an administrator that did not use it").isEqualTo(HttpStatus.OK);
        assertThat(body(mine).get("userId").asText()).isEqualTo(second.userId());
        assertThat(status(login(second.email(), "other-admins-passphrase"))).isEqualTo(HttpStatus.OK);
        assertThat(status(login(first.email(), NEW_PASSWORD))).isEqualTo(HttpStatus.OK);
    }

    // ── the receipt (ADR-021 Decision 2) ─────────────────────────────

    // Moves the receipt's own clock, which only the instance administrator may do: auth_app can neither update nor delete it.
    private void expireReceipt(String actorId, String key) throws Exception {
        try (java.sql.Connection c = java.sql.DriverManager.getConnection(System.getenv("TEST_DATABASE_URL"),
                System.getenv().getOrDefault("TEST_ADMIN_DATABASE_USER", "postgres"), System.getenv("TEST_ADMIN_DATABASE_PASSWORD"));
             java.sql.PreparedStatement s = c.prepareStatement(
                 "UPDATE auth_schema.password_reset_receipt SET expires_at = clock_timestamp() - interval '1 second' WHERE audit_id = "
                     + "(SELECT audit_id FROM auth_schema.password_reset_audit WHERE actor_user_id = ?::uuid AND idempotency_key = ?)")) {
            s.setString(1, actorId);
            s.setString(2, key);
            assertThat(s.executeUpdate()).isEqualTo(1);
        }
    }

    @Test
    @Tag("AUTH-RESET-13")
    void k1SetsA_k2SetsB_k1PlusAAnswersTheOriginalResult_withoutRestoringAOrRevokingTheNewSessions() throws Exception {
        Account admin = newAccount("ADMIN", true);
        Account target = newAccount("SALESPERSON", true);
        String k1 = newKey();
        String k2 = newKey();
        String passwordA = "passphrase-a-" + UUID.randomUUID();
        String passwordB = "passphrase-b-" + UUID.randomUUID();
        JsonNode original = body(reset(admin, target.userId(), k1, passwordA));
        assertThat(status(reset(admin, target.userId(), k2, passwordB))).isEqualTo(HttpStatus.OK);
        JsonNode sessionAfterB = body(login(target.email(), passwordB));

        ResponseEntity<String> replay = reset(admin, target.userId(), k1, passwordA);

        assertThat(status(replay)).as("K1 + A is the request K1 did, even though B is the password now").isEqualTo(HttpStatus.OK);
        assertThat(body(replay)).isEqualTo(original);
        assertThat(status(login(target.email(), passwordA))).as("A was not restored").isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(status(login(target.email(), passwordB))).isEqualTo(HttpStatus.OK);
        assertThat(status(refresh(sessionAfterB.get("refreshToken").asText()))).as("the replay revoked nothing").isEqualTo(HttpStatus.OK);
        assertThat(resetAudits(target.userId())).isEqualTo(2);
        ResponseEntity<String> k1WithB = reset(admin, target.userId(), k1, passwordB);
        assertThat(status(k1WithB)).as("K1 + B is not what K1 did").isEqualTo(HttpStatus.UNPROCESSABLE_ENTITY);
        assertThat(k1WithB.getBody()).doesNotContain(passwordA).doesNotContain(passwordB);
    }

    @Test
    @Tag("AUTH-RESET-13")
    void anExpiredReceipt_is422OnTheKey_changesNothing_andNeverFreesTheKey() throws Exception {
        Account admin = newAccount("ADMIN", true);
        Account target = newAccount("SALESPERSON", true);
        String key = newKey();
        assertThat(status(reset(admin, target.userId(), key, NEW_PASSWORD))).isEqualTo(HttpStatus.OK);
        String hashAfterTheReset = jdbc.queryForObject("SELECT password_hash FROM auth_schema.system_user WHERE user_id = ?::uuid", String.class, target.userId());
        expireReceipt(admin.userId(), key);

        ResponseEntity<String> late = reset(admin, target.userId(), key, NEW_PASSWORD);

        assertThat(status(late)).isEqualTo(HttpStatus.UNPROCESSABLE_ENTITY);
        assertThat(body(late).get("details").get(0).get("field").asText()).isEqualTo("Idempotency-Key");
        assertThat(late.getBody()).doesNotContain(NEW_PASSWORD).doesNotContain(hashAfterTheReset);
        assertThat(jdbc.queryForObject("SELECT password_hash FROM auth_schema.system_user WHERE user_id = ?::uuid", String.class, target.userId()))
            .as("not executed again").isEqualTo(hashAfterTheReset);
        assertThat(resetAudits(target.userId())).isEqualTo(1);
        assertThat(status(reset(admin, target.userId(), key, "another-passphrase-entirely"))).as("the key is still consumed").isEqualTo(HttpStatus.UNPROCESSABLE_ENTITY);
        assertThat(status(reset(admin, target.userId(), newKey(), "another-passphrase-entirely"))).as("a new key is a new operation").isEqualTo(HttpStatus.OK);
    }

    @Test
    @Tag("AUTH-RESET-14")
    void twoSimultaneousRequestsWithTheSameKey_changeThePasswordOnce_andBothAnswer200() throws Exception {
        for (int round = 0; round < 3; round++) {
            Account admin = newAccount("ADMIN", true);
            Account target = newAccount("SALESPERSON", true);
            String key = newKey();
            ExecutorService pool = Executors.newFixedThreadPool(2);
            List<Future<ResponseEntity<String>>> futures = new ArrayList<>();
            for (int i = 0; i < 2; i++) {
                futures.add(pool.submit(() -> reset(admin, target.userId(), key, NEW_PASSWORD)));
            }
            List<JsonNode> bodies = new ArrayList<>();
            for (Future<ResponseEntity<String>> future : futures) {
                ResponseEntity<String> response = future.get();
                assertThat(status(response)).isEqualTo(HttpStatus.OK);
                bodies.add(body(response));
            }
            pool.shutdown();

            assertThat(bodies.get(0)).isEqualTo(bodies.get(1));
            assertThat(resetAudits(target.userId())).isEqualTo(1);
            assertThat(status(login(target.email(), NEW_PASSWORD))).isEqualTo(HttpStatus.OK);
        }
    }

    // ── an uncertain outcome ─────────────────────────────────────────

    @Test
    @Tag("AUTH-RESET-15")
    void aResponseLostAfterTheCommit_isAnUncertain500_andTheSameKeyRetryAnswersTheCommittedResult() throws Exception {
        Account admin = newAccount("ADMIN", true);
        Account target = newAccount("SALESPERSON", true);
        String key = newKey();
        FAULTS.put(key, Fault.AFTER_COMMIT);

        ResponseEntity<String> lost = reset(admin, target.userId(), key, NEW_PASSWORD);

        assertThat(status(lost)).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(body(lost).get("error").asText()).isEqualTo("INTERNAL_ERROR");
        assertThat(resetAudits(target.userId())).as("the work was committed although the answer says 500").isEqualTo(1);

        FAULTS.remove(key);
        ResponseEntity<String> retry = reset(admin, target.userId(), key, NEW_PASSWORD);

        assertThat(status(retry)).isEqualTo(HttpStatus.OK);
        assertThat(body(retry).get("userId").asText()).isEqualTo(target.userId());
        assertThat(resetAudits(target.userId())).isEqualTo(1);
        assertThat(status(login(target.email(), NEW_PASSWORD))).isEqualTo(HttpStatus.OK);
    }

    @Test
    @Tag("AUTH-RESET-15")
    void aFailureBeforeTheCommit_changesNothing_andTheSameKeyRetryThenExecutes() throws Exception {
        Account admin = newAccount("ADMIN", true);
        Account target = newAccount("SALESPERSON", true);
        String key = newKey();
        FAULTS.put(key, Fault.BEFORE_COMMIT);

        ResponseEntity<String> failed = reset(admin, target.userId(), key, NEW_PASSWORD);

        assertThat(status(failed)).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(resetAudits(target.userId())).isZero();
        assertThat(status(login(target.email(), OLD_PASSWORD))).isEqualTo(HttpStatus.OK);

        FAULTS.remove(key);
        ResponseEntity<String> retry = reset(admin, target.userId(), key, NEW_PASSWORD);

        assertThat(status(retry)).isEqualTo(HttpStatus.OK);
        assertThat(resetAudits(target.userId())).isEqualTo(1);
        assertThat(status(login(target.email(), NEW_PASSWORD))).isEqualTo(HttpStatus.OK);
    }

    @Test
    @Tag("AUTH-RESET-16")
    void aFailingAuditWrite_isA500_withNoNewPassword_noRevocation_andNoKey() throws Exception {
        Account admin = newAccount("ADMIN", true);
        Account target = newAccount("SALESPERSON", true);
        String key = newKey();
        int active = activeRefreshRows(target.userId());
        FAULTS.put(key, Fault.CORRUPT_AUDIT);

        ResponseEntity<String> response = reset(admin, target.userId(), key, NEW_PASSWORD);

        assertThat(status(response)).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(response.getBody()).doesNotContain("password_reset_audit").doesNotContain("constraint").doesNotContain(NEW_PASSWORD);
        assertThat(count("SELECT count(*) FROM auth_schema.password_reset_audit WHERE idempotency_key = ?", key)).isZero();
        assertThat(activeRefreshRows(target.userId())).isEqualTo(active);
        assertThat(status(login(target.email(), OLD_PASSWORD))).isEqualTo(HttpStatus.OK);
        assertThat(status(login(target.email(), NEW_PASSWORD))).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    // ── nothing secret is logged ─────────────────────────────────────

    @Test
    @Tag("AUTH-RESET-17")
    void refusalsAreInTheSecurityLog_andNeitherThatNorAnyOtherLogHoldsAPasswordAHashOrAToken() throws Exception {
        Account admin = newAccount("ADMIN", true);
        Account salesperson = newAccount("SALESPERSON", true);
        Account inactive = newAccount("SALESPERSON", false);
        Account target = newAccount("SALESPERSON", true);
        String forbidden = "corr-403-" + UUID.randomUUID();
        String refusedTarget = "corr-422-" + UUID.randomUUID();
        String invalid = "corr-400-" + UUID.randomUUID();
        String failed = "corr-500-" + UUID.randomUUID();
        String failingKey = newKey();
        FAULTS.put(failingKey, Fault.BEFORE_COMMIT);
        int audits = totalResetAudits();

        reset(salesperson, target.userId(), newKey(), passwordBody(NEW_PASSWORD), forbidden);
        reset(admin, inactive.userId(), newKey(), passwordBody(NEW_PASSWORD), refusedTarget);
        reset(admin, target.userId(), newKey(), passwordBody(SHORT_PASSWORD), invalid);
        reset(admin, target.userId(), failingKey, passwordBody(NEW_PASSWORD), failed);
        ResponseEntity<String> success = reset(admin, target.userId(), newKey(), passwordBody(NEW_PASSWORD), "corr-ok-" + UUID.randomUUID());

        assertThat(status(success)).isEqualTo(HttpStatus.OK);
        assertThat(securityEventsOf(forbidden)).singleElement().satisfies(e -> assertThat(e.getFormattedMessage())
            .contains("event=PASSWORD_RESET_REJECTED").contains("reason=FORBIDDEN").contains("caller=" + salesperson.userId()));
        assertThat(securityEventsOf(refusedTarget)).singleElement().satisfies(e -> assertThat(e.getFormattedMessage())
            .contains("reason=BUSINESS_RULE").contains("target=" + inactive.userId()));
        assertThat(securityEventsOf(invalid)).singleElement().satisfies(e -> assertThat(e.getFormattedMessage())
            .contains("reason=INVALID_REQUEST"));
        assertThat(securityEventsOf(failed)).singleElement().satisfies(e -> assertThat(e.getFormattedMessage())
            .contains("reason=FAILED"));
        assertThat(totalResetAudits()).as("only the success is audited, refusals live in the log").isEqualTo(audits + 1);

        String newHash = jdbc.queryForObject("SELECT password_hash FROM auth_schema.system_user WHERE user_id = ?::uuid", String.class, target.userId());
        assertThat(allLoggedText()).doesNotContain(NEW_PASSWORD).doesNotContain(OLD_PASSWORD).doesNotContain(SHORT_PASSWORD)
            .doesNotContain(newHash).doesNotContain("$2a$").doesNotContain("$2b$")
            .doesNotContain(admin.accessToken()).doesNotContain(salesperson.accessToken()).doesNotContain(target.refreshToken());
    }
}
