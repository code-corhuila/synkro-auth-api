package co.edu.corhuila.synkro.auth.adapter.out.persistence.jdbc;

import co.edu.corhuila.synkro.auth.adapter.out.crypto.BcryptPasswordHasher;
import co.edu.corhuila.synkro.auth.application.port.out.UserRegistrationStore.CreationAttribution;
import co.edu.corhuila.synkro.auth.application.port.out.UserRegistrationStore.Registered;
import co.edu.corhuila.synkro.auth.application.usecase.BusinessRuleViolationException;
import co.edu.corhuila.synkro.auth.domain.model.SystemUser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The user, its idempotency key and its USER_REGISTERED audit row are one unit on one connection, checked on
 * the real auth_schema as auth_app: the audit table lets the service insert and read, never update or delete.
 */
@EnabledIfEnvironmentVariable(named = PostgresTestDatabase.URL_VARIABLE, matches = ".+")
class JdbcUserRegistrationAuditIntegrationTest {

    private final BcryptPasswordHasher hasher = new BcryptPasswordHasher();
    private JdbcTemplate jdbc;
    private JdbcUserRegistrationStore store;
    private String actorId;

    @BeforeEach
    void setUp() {
        jdbc = PostgresTestDatabase.jdbcTemplate();
        store = new JdbcUserRegistrationStore(jdbc, PostgresTestDatabase.transactions(jdbc));
        actorId = PostgresTestDatabase.insertUser(jdbc, "ADMIN", true);
    }

    private static String newKey() {
        return "it-key-" + UUID.randomUUID();
    }

    private SystemUser newUser(String email) {
        return new SystemUser(UUID.randomUUID().toString(), "Ana Perez", email, hasher.hash("a-long-password"),
            "SALESPERSON", Instant.now().truncatedTo(ChronoUnit.MICROS), true);
    }

    private CreationAttribution attribution(String actor, String correlationId) {
        return new CreationAttribution(UUID.randomUUID().toString(), actor, Instant.now().truncatedTo(ChronoUnit.MICROS), correlationId);
    }

    private int auditRowsOf(String userId) {
        return jdbc.queryForObject("SELECT count(*) FROM auth_schema.user_creation_audit WHERE created_user_id = ?::uuid",
            Integer.class, userId);
    }

    private int usersWithEmail(String email) {
        return jdbc.queryForObject("SELECT count(*) FROM auth_schema.system_user WHERE email = ?", Integer.class, email);
    }

    private int keysNamed(String key) {
        return jdbc.queryForObject("SELECT count(*) FROM auth_schema.idempotency_key WHERE key = ?", Integer.class, key);
    }

    // ── AUTH-REG-04, case 14 ─────────────────────────────────────────

    @Test
    @Tag("AUTH-REG-04")
    void case14_theFirstCreate_leavesTheUser_theKey_andOneUserRegisteredAuditRow() {
        String key = newKey();
        SystemUser user = newUser(PostgresTestDatabase.uniqueEmail());
        CreationAttribution attribution = attribution(actorId, "corr-" + UUID.randomUUID());

        Registered saved = store.registerUserWithAttribution(key, user, attribution);

        assertThat(saved.created()).isTrue();
        assertThat(usersWithEmail(user.getEmail())).isEqualTo(1);
        assertThat(keysNamed(key)).isEqualTo(1);
        Map<String, Object> audit = jdbc.queryForMap(
            "SELECT audit_id::text AS audit_id, operation, actor_kind, actor_user_id::text AS actor_user_id, operator_identity, "
                + "created_user_id::text AS created_user_id, outcome, occurred_at, correlation_id "
                + "FROM auth_schema.user_creation_audit WHERE created_user_id = ?::uuid", user.getUserId());
        assertThat(audit.get("audit_id")).isEqualTo(attribution.auditId());
        assertThat(audit.get("operation")).isEqualTo("USER_REGISTERED");
        assertThat(audit.get("actor_kind")).isEqualTo("ADMIN");
        assertThat(audit.get("actor_user_id")).isEqualTo(actorId);
        assertThat(audit.get("operator_identity")).isNull();
        assertThat(audit.get("created_user_id")).isEqualTo(user.getUserId());
        assertThat(audit.get("outcome")).isEqualTo("SUCCESS");
        assertThat(((java.sql.Timestamp) audit.get("occurred_at")).toInstant()).isEqualTo(attribution.occurredAt());
        assertThat(audit.get("correlation_id")).isEqualTo(attribution.correlationId());
    }

    // ── case 11, at the store ────────────────────────────────────────

    @Test
    @Tag("AUTH-REG-04")
    void case11_replayingTheSameKey_writesNoSecondAuditRow() {
        String key = newKey();
        SystemUser user = newUser(PostgresTestDatabase.uniqueEmail());
        store.registerUserWithAttribution(key, user, attribution(actorId, "corr-first"));

        for (int replay = 0; replay < 3; replay++) {
            Registered again = store.registerUserWithAttribution(key, newUser(user.getEmail()), attribution(actorId, "corr-replay-" + replay));
            assertThat(again.created()).isFalse();
        }

        assertThat(auditRowsOf(user.getUserId())).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT correlation_id FROM auth_schema.user_creation_audit WHERE created_user_id = ?::uuid",
            String.class, user.getUserId())).isEqualTo("corr-first");
    }

    // ── case 15: a failing audit write undoes the user and the key ───

    @Test
    @Tag("AUTH-REG-04")
    void case15_anAuditWriteThatFails_rollsBackTheUserAndTheKeyToo() {
        String key = newKey();
        SystemUser user = newUser(PostgresTestDatabase.uniqueEmail());
        // The audit row is the last write and names a creator that does not exist, so its foreign key fails.
        CreationAttribution unknownCreator = attribution(UUID.randomUUID().toString(), "corr-" + UUID.randomUUID());

        assertThatThrownBy(() -> store.registerUserWithAttribution(key, user, unknownCreator)).isInstanceOf(DataAccessException.class);

        assertThat(usersWithEmail(user.getEmail())).isZero();
        assertThat(keysNamed(key)).isZero();
        assertThat(auditRowsOf(user.getUserId())).isZero();
    }

    @Test
    @Tag("AUTH-REG-04")
    void case15b_anAuditRowThatBreaksItsOwnConstraint_rollsBackTheUserAndTheKeyToo() {
        String key = newKey();
        SystemUser user = newUser(PostgresTestDatabase.uniqueEmail());
        CreationAttribution noCorrelation = attribution(actorId, "");

        assertThatThrownBy(() -> store.registerUserWithAttribution(key, user, noCorrelation)).isInstanceOf(DataAccessException.class);

        assertThat(usersWithEmail(user.getEmail())).isZero();
        assertThat(keysNamed(key)).isZero();
        assertThat(auditRowsOf(user.getUserId())).isZero();
    }

    @Test
    @Tag("AUTH-REG-04")
    void case15c_aDuplicateEmail_leavesNoKeyAndNoAuditRow() {
        SystemUser first = newUser(PostgresTestDatabase.uniqueEmail());
        store.registerUserWithAttribution(newKey(), first, attribution(actorId, "corr-first"));
        String secondKey = newKey();
        SystemUser second = newUser(first.getEmail());

        assertThatThrownBy(() -> store.registerUserWithAttribution(secondKey, second, attribution(actorId, "corr-second")))
            .isInstanceOf(BusinessRuleViolationException.class);

        assertThat(keysNamed(secondKey)).isZero();
        assertThat(auditRowsOf(second.getUserId())).isZero();
        assertThat(auditRowsOf(first.getUserId())).isEqualTo(1);
    }

    // ── case 16: concurrent requests with the same key ───────────────

    private <T> List<Object> runTogether(List<Callable<T>> tasks) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(tasks.size());
        CountDownLatch ready = new CountDownLatch(tasks.size());
        CountDownLatch go = new CountDownLatch(1);
        List<Future<Object>> futures = new ArrayList<>();
        for (Callable<T> task : tasks) {
            futures.add(pool.submit(() -> {
                ready.countDown();
                go.await();
                try {
                    return task.call();
                } catch (Exception e) {
                    return e;
                }
            }));
        }
        ready.await();
        go.countDown();
        List<Object> outcomes = new ArrayList<>();
        for (Future<Object> future : futures) {
            outcomes.add(future.get());
        }
        pool.shutdown();
        return outcomes;
    }

    @Test
    @Tag("AUTH-REG-04")
    void case16_concurrentRequestsWithTheSameKey_createOneUser_andWriteExactlyOneAuditRow() throws Exception {
        for (int round = 0; round < 10; round++) {
            String key = newKey();
            String email = PostgresTestDatabase.uniqueEmail();
            SystemUser a = newUser(email);
            SystemUser b = newUser(email);

            List<Object> outcomes = runTogether(List.of(
                () -> store.registerUserWithAttribution(key, a, attribution(actorId, "corr-a")),
                () -> store.registerUserWithAttribution(key, b, attribution(actorId, "corr-b")),
                () -> store.registerUserWithAttribution(key, newUser(email), attribution(actorId, "corr-c"))));

            assertThat(outcomes).allSatisfy(o -> assertThat(o).isInstanceOf(Registered.class));
            List<Registered> results = outcomes.stream().map(Registered.class::cast).toList();
            assertThat(results).filteredOn(Registered::created).hasSize(1);
            String winnerId = results.stream().filter(Registered::created).findFirst().orElseThrow().user().getUserId();
            assertThat(results).extracting(r -> r.user().getUserId()).containsOnly(winnerId);
            assertThat(usersWithEmail(email)).isEqualTo(1);
            assertThat(keysNamed(key)).isEqualTo(1);
            assertThat(auditRowsOf(winnerId)).isEqualTo(1);
        }
    }
}
