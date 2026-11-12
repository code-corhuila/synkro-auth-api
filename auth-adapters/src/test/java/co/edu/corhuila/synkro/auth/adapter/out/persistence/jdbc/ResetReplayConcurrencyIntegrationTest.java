package co.edu.corhuila.synkro.auth.adapter.out.persistence.jdbc;

import co.edu.corhuila.synkro.auth.adapter.out.crypto.BcryptPasswordHasher;
import co.edu.corhuila.synkro.auth.application.usecase.BusinessRuleViolationException;
import co.edu.corhuila.synkro.auth.application.usecase.ResetUserPasswordCommand;
import co.edu.corhuila.synkro.auth.application.usecase.ResetUserPasswordResult;
import co.edu.corhuila.synkro.auth.application.usecase.ResetUserPasswordUseCase;
import co.edu.corhuila.synkro.auth.domain.model.AuthenticatedCaller;
import co.edu.corhuila.synkro.auth.domain.model.Roles;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Replay by receipt with the real use case, the real bcrypt and PostgreSQL, under concurrency (ADR-021 Decision 2):
 * one execution per key, a different payload under a taken key is refused, and keys and actors do not see each other.
 */
@EnabledIfEnvironmentVariable(named = PostgresTestDatabase.URL_VARIABLE, matches = ".+")
class ResetReplayConcurrencyIntegrationTest {

    private JdbcTemplate jdbc;
    private BcryptPasswordHasher hasher;
    private ResetUserPasswordUseCase reset;
    private ExecutorService pool;

    @BeforeEach
    void setUp() {
        jdbc = PostgresTestDatabase.jdbcTemplate();
        hasher = new BcryptPasswordHasher();
        reset = new ResetUserPasswordUseCase(new JdbcUserRepository(jdbc),
            new JdbcPasswordResetStore(jdbc, PostgresTestDatabase.transactions(jdbc)), hasher,
            () -> UUID.randomUUID().toString(), Clock.systemUTC(), (correlationId, callerId, target, reason) -> {});
        pool = Executors.newFixedThreadPool(8);
    }

    @AfterEach
    void tearDown() {
        pool.shutdownNow();
    }

    private AuthenticatedCaller newAdmin() {
        String id = PostgresTestDatabase.insertUser(jdbc, "Admin", PostgresTestDatabase.uniqueEmail(), hasher.hash("an-admin-passphrase"), "ADMIN", true);
        return new AuthenticatedCaller(id, Set.of(Roles.ADMIN), Set.of());
    }

    private String newTarget() {
        return PostgresTestDatabase.insertUser(jdbc, "Target", PostgresTestDatabase.uniqueEmail(), hasher.hash("the-old-passphrase"), "SALESPERSON", true);
    }

    private ResetUserPasswordResult run(AuthenticatedCaller admin, String targetId, String key, String password) {
        return reset.execute(admin, "corr-" + UUID.randomUUID(), new ResetUserPasswordCommand(targetId, key, password, password));
    }

    private int audits(String actorId, String key) {
        return jdbc.queryForObject("SELECT count(*) FROM auth_schema.password_reset_audit WHERE actor_user_id = ?::uuid AND idempotency_key = ?",
            Integer.class, actorId, key);
    }

    private boolean passwordIs(String userId, String plaintext) {
        return hasher.matches(plaintext, jdbc.queryForObject("SELECT password_hash FROM auth_schema.system_user WHERE user_id = ?::uuid", String.class, userId));
    }

    /** Releases every task at the same moment so they really overlap; the gate orders nothing else. */
    private <T> List<Future<T>> together(List<Callable<T>> tasks) {
        CountDownLatch start = new CountDownLatch(1);
        List<Future<T>> futures = new ArrayList<>();
        for (Callable<T> task : tasks) {
            futures.add(pool.submit(() -> {
                start.await();
                return task.call();
            }));
        }
        start.countDown();
        return futures;
    }

    @Test
    @Tag("AUTH-RESET-14")
    void sameKeySamePasswordInParallel_executesOnce_andEveryoneAnswersTheSameResult() throws Exception {
        AuthenticatedCaller admin = newAdmin();
        String targetId = newTarget();
        String key = "it-conc-" + UUID.randomUUID();
        String password = "passphrase-" + UUID.randomUUID();

        List<Callable<ResetUserPasswordResult>> tasks = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            tasks.add(() -> run(admin, targetId, key, password));
        }
        List<ResetUserPasswordResult> results = new ArrayList<>();
        for (Future<ResetUserPasswordResult> f : together(tasks)) {
            results.add(f.get());
        }

        assertThat(results).extracting(ResetUserPasswordResult::passwordResetAt).containsOnly(results.get(0).passwordResetAt());
        assertThat(results.stream().filter(r -> !r.replayed()).count()).as("exactly one executed").isEqualTo(1);
        assertThat(audits(admin.subject(), key)).isEqualTo(1);
        assertThat(passwordIs(targetId, password)).isTrue();
    }

    @Test
    @Tag("AUTH-RESET-14")
    void sameKeyWithDifferentPasswordsInParallel_oneWins_theOtherIs422_andTheWinnersPasswordStays() throws Exception {
        AuthenticatedCaller admin = newAdmin();
        String targetId = newTarget();
        String key = "it-conc-" + UUID.randomUUID();
        String a = "passphrase-a-" + UUID.randomUUID();
        String b = "passphrase-b-" + UUID.randomUUID();

        List<Callable<Object>> tasks = List.<Callable<Object>>of(() -> run(admin, targetId, key, a), () -> run(admin, targetId, key, b));
        int successes = 0;
        int refusals = 0;
        for (Future<Object> f : together(tasks)) {
            try {
                f.get();
                successes++;
            } catch (java.util.concurrent.ExecutionException e) {
                assertThat(e.getCause()).isInstanceOf(BusinessRuleViolationException.class);
                refusals++;
            }
        }

        assertThat(successes).isEqualTo(1);
        assertThat(refusals).isEqualTo(1);
        assertThat(audits(admin.subject(), key)).isEqualTo(1);
        assertThat(passwordIs(targetId, a) ^ passwordIs(targetId, b)).as("exactly one of the two passwords is in force").isTrue();
    }

    @Test
    @Tag("AUTH-RESET-14")
    void sameKeyWithAnotherTarget_isRefusedWhileTheFirstIsValid() throws Exception {
        AuthenticatedCaller admin = newAdmin();
        String first = newTarget();
        String second = newTarget();
        String key = "it-conc-" + UUID.randomUUID();
        String password = "passphrase-" + UUID.randomUUID();
        run(admin, first, key, password);

        try {
            run(admin, second, key, password);
            throw new AssertionError("expected a refusal");
        } catch (BusinessRuleViolationException expected) {
            assertThat(passwordIs(second, password)).as("the second target is untouched").isFalse();
        }
    }

    @Test
    @Tag("AUTH-RESET-14")
    void sameKeyTextUsedByDifferentActorsInParallel_isTwoIndependentOperations() throws Exception {
        AuthenticatedCaller one = newAdmin();
        AuthenticatedCaller other = newAdmin();
        String targetOne = newTarget();
        String targetOther = newTarget();
        String key = "it-conc-" + UUID.randomUUID();
        String passwordOne = "passphrase-one-" + UUID.randomUUID();
        String passwordOther = "passphrase-other-" + UUID.randomUUID();

        List<Callable<ResetUserPasswordResult>> tasks = List.<Callable<ResetUserPasswordResult>>of(
            () -> run(one, targetOne, key, passwordOne), () -> run(other, targetOther, key, passwordOther));
        for (Future<ResetUserPasswordResult> f : together(tasks)) {
            assertThat(f.get().replayed()).isFalse();
        }

        assertThat(passwordIs(targetOne, passwordOne)).isTrue();
        assertThat(passwordIs(targetOther, passwordOther)).isTrue();
        assertThat(audits(one.subject(), key)).isEqualTo(1);
        assertThat(audits(other.subject(), key)).isEqualTo(1);
    }

    @Test
    @Tag("AUTH-RESET-14")
    void twoKeysOnTheSameTargetInParallel_bothExecute_andEachKeyKeepsItsOwnReceipt() throws Exception {
        AuthenticatedCaller admin = newAdmin();
        String targetId = newTarget();
        String k1 = "it-conc-" + UUID.randomUUID();
        String k2 = "it-conc-" + UUID.randomUUID();
        String a = "passphrase-a-" + UUID.randomUUID();
        String b = "passphrase-b-" + UUID.randomUUID();

        for (Future<ResetUserPasswordResult> f : together(List.<Callable<ResetUserPasswordResult>>of(() -> run(admin, targetId, k1, a), () -> run(admin, targetId, k2, b)))) {
            assertThat(f.get().replayed()).isFalse();
        }

        // Whichever committed last is in force, and both keys still answer their own request.
        assertThat(run(admin, targetId, k1, a).replayed()).isTrue();
        assertThat(run(admin, targetId, k2, b).replayed()).isTrue();
        assertThat(passwordIs(targetId, a) ^ passwordIs(targetId, b)).isTrue();
        assertThat(audits(admin.subject(), k1) + audits(admin.subject(), k2)).isEqualTo(2);
    }
}
