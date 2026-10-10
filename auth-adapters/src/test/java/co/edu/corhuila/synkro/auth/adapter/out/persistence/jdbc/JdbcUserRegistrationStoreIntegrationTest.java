package co.edu.corhuila.synkro.auth.adapter.out.persistence.jdbc;

import co.edu.corhuila.synkro.auth.adapter.out.crypto.BcryptPasswordHasher;
import co.edu.corhuila.synkro.auth.application.port.out.UserRegistrationStore.Registered;
import co.edu.corhuila.synkro.auth.application.usecase.BusinessRuleViolationException;
import co.edu.corhuila.synkro.auth.domain.model.SystemUser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.dao.DataIntegrityViolationException;
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

@EnabledIfEnvironmentVariable(named = PostgresTestDatabase.URL_VARIABLE, matches = ".+")
class JdbcUserRegistrationStoreIntegrationTest {

    private final BcryptPasswordHasher hasher = new BcryptPasswordHasher();
    private JdbcTemplate jdbc;
    private JdbcUserRegistrationStore store;

    @BeforeEach
    void setUp() {
        jdbc = PostgresTestDatabase.jdbcTemplate();
        store = new JdbcUserRegistrationStore(jdbc, PostgresTestDatabase.transactions(jdbc));
    }

    private static String newKey() {
        return "it-key-" + UUID.randomUUID();
    }

    private SystemUser newUser(String email) {
        return new SystemUser(UUID.randomUUID().toString(), "Ana Perez", email, hasher.hash("a-long-password"),
            "SALESPERSON", Instant.now().truncatedTo(ChronoUnit.MICROS), true);
    }

    private int usersWithEmail(String email) {
        return jdbc.queryForObject("SELECT count(*) FROM auth_schema.system_user WHERE email = ?", Integer.class, email);
    }

    private int keysNamed(String key) {
        return jdbc.queryForObject("SELECT count(*) FROM auth_schema.idempotency_key WHERE key = ?", Integer.class, key);
    }

    // ── insert ───────────────────────────────────────────────────────

    @Test
    void registerOnce_persistsEveryColumnOfTheUser_andTheBcryptHashRoundTrips() {
        SystemUser user = newUser(PostgresTestDatabase.uniqueEmail());

        Registered saved = store.registerOnce(newKey(), user);

        assertThat(saved.created()).isTrue();
        Map<String, Object> row = jdbc.queryForMap(
            "SELECT user_id::text AS id, name, email, password_hash, role, registration_date, active "
                + "FROM auth_schema.system_user WHERE user_id = ?::uuid", user.getUserId());
        assertThat(row.get("id")).isEqualTo(user.getUserId());
        assertThat(row.get("name")).isEqualTo("Ana Perez");
        assertThat(row.get("email")).isEqualTo(user.getEmail());
        assertThat(row.get("password_hash")).isEqualTo(user.getPasswordHash());
        assertThat((String) row.get("password_hash")).startsWith("$2");
        assertThat(hasher.matches("a-long-password", (String) row.get("password_hash"))).isTrue();
        assertThat(row.get("role")).isEqualTo("SALESPERSON");
        assertThat(row.get("active")).isEqualTo(true);
        assertThat(((java.sql.Timestamp) row.get("registration_date")).toInstant()).isEqualTo(user.getRegistrationDate());
    }

    @Test
    void theUserReadBackThroughTheRepository_equalsWhatWasRegistered() {
        SystemUser user = newUser(PostgresTestDatabase.uniqueEmail());
        store.registerOnce(newKey(), user);

        SystemUser read = new JdbcUserRepository(jdbc).findById(user.getUserId()).orElseThrow();

        assertThat(read.getRegistrationDate()).isEqualTo(user.getRegistrationDate());
        assertThat(read.getPasswordHash()).isEqualTo(user.getPasswordHash());
    }

    @Test
    void aDuplicateEmailWithANewKey_isTheTypedBusinessRuleError_andLeavesNoKeyBehind() {
        String email = PostgresTestDatabase.uniqueEmail();
        store.registerOnce(newKey(), newUser(email));
        String secondKey = newKey();

        assertThatThrownBy(() -> store.registerOnce(secondKey, newUser(email)))
            .isInstanceOfSatisfying(BusinessRuleViolationException.class, e -> assertThat(e.field()).isEqualTo("email"));

        assertThat(usersWithEmail(email)).isEqualTo(1);
        assertThat(keysNamed(secondKey)).isZero();
    }

    // ── idempotency store ────────────────────────────────────────────

    @Test
    void theKeyIsSavedAsTypeUserPointingAtTheUser_andCanBeFound() {
        String key = newKey();
        SystemUser user = newUser(PostgresTestDatabase.uniqueEmail());
        store.registerOnce(key, user);

        Map<String, Object> row = jdbc.queryForMap(
            "SELECT resource_type, resource_id::text AS resource_id FROM auth_schema.idempotency_key WHERE key = ?", key);
        assertThat(row.get("resource_type")).isEqualTo("USER");
        assertThat(row.get("resource_id")).isEqualTo(user.getUserId());
        assertThat(store.findByIdempotencyKey(key)).get().extracting(SystemUser::getUserId).isEqualTo(user.getUserId());
        assertThat(store.findByIdempotencyKey(newKey())).isEmpty();
    }

    @Test
    void aKeyOfAnotherResourceType_isNotAUser() {
        String key = newKey();
        jdbc.update("INSERT INTO auth_schema.idempotency_key (key, resource_type, resource_id) VALUES (?, 'SERVICE_TOKEN', ?::uuid)",
            key, UUID.randomUUID().toString());

        assertThat(store.findByIdempotencyKey(key)).isEmpty();
    }

    @Test
    void aDuplicateKey_isDetected_returningTheOriginalUser_andCreatingNothing() {
        String key = newKey();
        SystemUser first = newUser(PostgresTestDatabase.uniqueEmail());
        String otherEmail = PostgresTestDatabase.uniqueEmail();
        store.registerOnce(key, first);

        Registered again = store.registerOnce(key, newUser(otherEmail));

        assertThat(again.created()).isFalse();
        assertThat(again.user().getUserId()).isEqualTo(first.getUserId());
        assertThat(usersWithEmail(otherEmail)).isZero();
        assertThat(keysNamed(key)).isEqualTo(1);
    }

    // ── atomicity ────────────────────────────────────────────────────

    @Test
    void ifTheSecondWriteFails_theFirstIsRolledBack_neitherTheUserNorTheKeyExists() {
        String key = newKey();
        String email = PostgresTestDatabase.uniqueEmail();
        SystemUser tooLongName = new SystemUser(UUID.randomUUID().toString(), "n".repeat(151), email,
            hasher.hash("a-long-password"), "ADMIN", Instant.now().truncatedTo(ChronoUnit.MICROS), true);

        assertThatThrownBy(() -> store.registerOnce(key, tooLongName)).isInstanceOf(DataIntegrityViolationException.class);

        assertThat(usersWithEmail(email)).isZero();
        assertThat(keysNamed(key)).isZero();
    }

    // ── concurrency ──────────────────────────────────────────────────

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
    void twoSimultaneousRegistrationsWithTheSameKey_createOneUser_andBothSucceed() throws Exception {
        for (int round = 0; round < 5; round++) {
            String key = newKey();
            String email = PostgresTestDatabase.uniqueEmail();

            List<Object> outcomes = runTogether(List.of(
                () -> store.registerOnce(key, newUser(email)),
                () -> store.registerOnce(key, newUser(email))));

            assertThat(outcomes).allSatisfy(o -> assertThat(o).isInstanceOf(Registered.class));
            List<Registered> results = outcomes.stream().map(Registered.class::cast).toList();
            assertThat(results).filteredOn(Registered::created).hasSize(1);
            assertThat(results.get(0).user().getUserId()).isEqualTo(results.get(1).user().getUserId());
            assertThat(usersWithEmail(email)).isEqualTo(1);
            assertThat(keysNamed(key)).isEqualTo(1);
        }
    }

    @Test
    void twoSimultaneousRegistrationsWithTheSameEmailAndDifferentKeys_createOneUser_andOneGetsTheBusinessRuleError() throws Exception {
        for (int round = 0; round < 5; round++) {
            String email = PostgresTestDatabase.uniqueEmail();
            String keyA = newKey();
            String keyB = newKey();

            List<Object> outcomes = runTogether(List.of(
                () -> store.registerOnce(keyA, newUser(email)),
                () -> store.registerOnce(keyB, newUser(email))));

            assertThat(outcomes).filteredOn(o -> o instanceof Registered r && r.created()).hasSize(1);
            assertThat(outcomes).filteredOn(o -> o instanceof BusinessRuleViolationException).hasSize(1);
            assertThat(usersWithEmail(email)).isEqualTo(1);
            assertThat(keysNamed(keyA) + keysNamed(keyB)).isEqualTo(1);
        }
    }
}
