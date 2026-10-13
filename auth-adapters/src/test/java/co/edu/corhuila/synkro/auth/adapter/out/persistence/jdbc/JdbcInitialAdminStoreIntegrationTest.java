package co.edu.corhuila.synkro.auth.adapter.out.persistence.jdbc;

import co.edu.corhuila.synkro.auth.application.port.out.InitialAdminStore.InitializationAudit;
import co.edu.corhuila.synkro.auth.application.usecase.InitialAdminResult;
import co.edu.corhuila.synkro.auth.application.usecase.BusinessRuleViolationException;
import co.edu.corhuila.synkro.auth.application.usecase.InitializationFailedException;
import co.edu.corhuila.synkro.auth.application.usecase.InitializationFailedException.Kind;
import co.edu.corhuila.synkro.auth.domain.model.SystemUser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static co.edu.corhuila.synkro.auth.adapter.out.persistence.jdbc.InitializationTestDatabase.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * HU-AUTH-14 on the real auth_schema, as auth_app: AUTH-INIT-01 (concurrency), AUTH-INIT-02 (repetition and
 * no-op) and AUTH-INIT-03 (rollback, retry and lock timeout).
 */
@EnabledIfEnvironmentVariable(named = PostgresTestDatabase.URL_VARIABLE, matches = ".+")
class JdbcInitialAdminStoreIntegrationTest {

    private static final String OPERATOR = "deploy-pipeline@release-7";

    @BeforeEach
    void emptyTheDisposableSchema() throws SQLException {
        reset();
    }

    private static SystemUser admin(String email, String hash) {
        return new SystemUser(UUID.randomUUID().toString(), "Ada Admin", email, hash, "ADMIN",
            Instant.now().truncatedTo(ChronoUnit.MICROS), true);
    }

    private static SystemUser admin() {
        return admin("ada-" + UUID.randomUUID() + "@synkro.test", "$2a$12$hash-of-the-initial-admin");
    }

    private static InitializationAudit audit(String correlationId) {
        return new InitializationAudit(UUID.randomUUID().toString(), OPERATOR,
            Instant.now().truncatedTo(ChronoUnit.MICROS), correlationId);
    }

    private static JdbcInitialAdminStore store() {
        return new JdbcInitialAdminStore(appConnections());
    }

    private static String insertUser(String role, boolean active, String email, String hash) throws SQLException {
        try (Connection c = appConnection(); PreparedStatement s = c.prepareStatement(
            "INSERT INTO auth_schema.system_user (name, email, password_hash, role, active) VALUES (?, ?, ?, ?, ?) "
                + "RETURNING user_id::text")) {
            s.setString(1, "Existing " + role);
            s.setString(2, email);
            s.setString(3, hash);
            s.setString(4, role);
            s.setBoolean(5, active);
            try (ResultSet rs = s.executeQuery()) {
                rs.next();
                return rs.getString(1);
            }
        }
    }

    private static String insertUser(String role, boolean active) throws SQLException {
        return insertUser(role, active, "it-" + UUID.randomUUID() + "@synkro.test", "$2a$12$existing-hash");
    }

    // ── AUTH-INIT-01: concurrency ───────────────────────────────────────────

    @Test
    void twoOverlappingExecutionsCreateExactlyOneAdministratorAndOneAudit() throws Exception {
        CountDownLatch firstHoldsTheLock = new CountDownLatch(1);
        CountDownLatch secondIsWaiting = new CountDownLatch(1);
        SystemUser first = admin();
        SystemUser second = admin();
        JdbcInitialAdminStore holder = new JdbcInitialAdminStore(appConnections(), connection -> {
            firstHoldsTheLock.countDown();
            // The lock is held until the other execution is observably queued behind it.
            assertThat(awaitQuietly(secondIsWaiting)).as("the second execution reached the lock").isTrue();
        });

        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<InitialAdminResult> firstRun = pool.submit(() -> holder.initializeAdministrator(first, audit("corr-first")));
            assertThat(firstHoldsTheLock.await(20, TimeUnit.SECONDS)).isTrue();
            assertThat(lockEntries(true)).as("the first execution holds the advisory lock").isEqualTo(1);

            Future<InitialAdminResult> secondRun = pool.submit(() -> store().initializeAdministrator(second, audit("corr-second")));
            awaitUntil(() -> lockEntries(false) == 1, "the second execution to wait on the advisory lock");
            assertThat(secondRun.isDone()).as("the second execution is blocked, not finished").isFalse();
            secondIsWaiting.countDown();

            assertThat(firstRun.get(30, TimeUnit.SECONDS)).extracting(InitialAdminResult::created).isEqualTo(true);
            assertThat(secondRun.get(30, TimeUnit.SECONDS)).extracting(InitialAdminResult::created).isEqualTo(false);
        } finally {
            secondIsWaiting.countDown();
            pool.shutdownNow();
        }

        assertThat(admins()).isEqualTo(1);
        assertThat(users()).isEqualTo(1);
        assertThat(initializationAudits()).isEqualTo(1);
        assertThat(count("SELECT count(*) FROM auth_schema.system_user WHERE user_id = ?::uuid", first.getUserId())).isEqualTo(1);
        assertThat(count("SELECT count(*) FROM auth_schema.system_user WHERE user_id = ?::uuid", second.getUserId())).isZero();
        assertThat(text("SELECT correlation_id FROM auth_schema.user_creation_audit WHERE created_user_id = ?::uuid",
            first.getUserId())).isEqualTo("corr-first");
        assertThat(lockEntries(true) + lockEntries(false)).as("the lock is released after commit").isZero();
    }

    @Test
    void manyOverlappingExecutionsStillCreateOneAdministrator() throws Exception {
        int executions = 6;
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(executions);
        List<Future<InitialAdminResult>> runs = new ArrayList<>();
        try {
            for (int i = 0; i < executions; i++) {
                String correlation = "corr-" + i;
                runs.add(pool.submit(() -> {
                    start.await();
                    return store().initializeAdministrator(admin(), audit(correlation));
                }));
            }
            start.countDown();
            List<InitialAdminResult> results = new ArrayList<>();
            for (Future<InitialAdminResult> run : runs) {
                results.add(run.get(60, TimeUnit.SECONDS));
            }
            assertThat(results).filteredOn(InitialAdminResult::created).hasSize(1);
            assertThat(results).filteredOn(r -> !r.created()).hasSize(executions - 1);
        } finally {
            pool.shutdownNow();
        }

        assertThat(admins()).isEqualTo(1);
        assertThat(initializationAudits()).isEqualTo(1);
    }

    @Test
    void theTransactionRunsReadCommittedOnOneAuthAppConnectionHoldingTheReservedKey() throws Exception {
        AtomicReference<String> isolation = new AtomicReference<>();
        AtomicReference<String> lockTimeout = new AtomicReference<>();
        AtomicReference<String> user = new AtomicReference<>();
        AtomicReference<Boolean> autoCommit = new AtomicReference<>();
        AtomicReference<Long> holders = new AtomicReference<>();
        AtomicReference<Long> holderIsThisBackend = new AtomicReference<>();
        JdbcInitialAdminStore inspected = new JdbcInitialAdminStore(appConnections(), connection -> {
            autoCommit.set(connection.getAutoCommit());
            isolation.set(scalar(connection, "SHOW transaction_isolation"));
            lockTimeout.set(scalar(connection, "SHOW lock_timeout"));
            user.set(scalar(connection, "SELECT current_user"));
            holders.set(Long.valueOf(scalar(connection, "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' "
                + "AND classid::bigint = 0 AND objid::bigint = " + LOCK_KEY + " AND objsubid = 1 AND granted")));
            holderIsThisBackend.set(Long.valueOf(scalar(connection, "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' "
                + "AND objid::bigint = " + LOCK_KEY + " AND granted AND pid = pg_backend_pid()")));
        });

        assertThat(inspected.initializeAdministrator(admin(), audit("corr-inspect"))).extracting(InitialAdminResult::created).isEqualTo(true);

        assertThat(autoCommit.get()).isFalse();
        assertThat(isolation.get()).isEqualTo("read committed");
        assertThat(lockTimeout.get()).isEqualTo("10s");
        assertThat(user.get()).isEqualTo("auth_app");
        assertThat(holders.get()).isEqualTo(1L);
        assertThat(holderIsThisBackend.get()).isEqualTo(1L);
        // Both settings were local to the transaction: a new session on the same role sees neither.
        try (Connection fresh = appConnection()) {
            assertThat(scalar(fresh, "SHOW lock_timeout")).isEqualTo("0");
        }
    }

    // ── AUTH-INIT-02: repetition and no-op ──────────────────────────────────

    @Test
    void anExistingActiveAdministratorMakesTheExecutionANoOp() throws Exception {
        String hash = "$2a$12$existing-admin-hash";
        String existing = insertUser("ADMIN", true, "keeper@synkro.test", hash);
        String before = text("SELECT name || '|' || email || '|' || password_hash || '|' || active FROM auth_schema.system_user");

        assertThat(store().initializeAdministrator(admin(), audit("corr-noop"))).extracting(InitialAdminResult::created).isEqualTo(false);

        assertThat(users()).isEqualTo(1);
        assertThat(audits()).isZero();
        assertThat(text("SELECT name || '|' || email || '|' || password_hash || '|' || active FROM auth_schema.system_user"))
            .isEqualTo(before);
        assertThat(text("SELECT user_id::text FROM auth_schema.system_user")).isEqualTo(existing);
        assertThat(lockEntries(true)).isZero();
    }

    @Test
    void anExistingInactiveAdministratorStillPreventsCreation() throws Exception {
        insertUser("ADMIN", false, "dormant@synkro.test", "$2a$12$dormant-admin-hash");

        assertThat(store().initializeAdministrator(admin(), audit("corr-inactive"))).extracting(InitialAdminResult::created).isEqualTo(false);

        assertThat(admins()).isEqualTo(1);
        assertThat(users()).isEqualTo(1);
        assertThat(audits()).isZero();
        assertThat(text("SELECT active::text FROM auth_schema.system_user")).isEqualTo("false");
        assertThat(text("SELECT password_hash FROM auth_schema.system_user")).isEqualTo("$2a$12$dormant-admin-hash");
    }

    @Test
    void usersWithOtherRolesDoNotCountAsAnAdministrator() throws Exception {
        insertUser("SALESPERSON", true);
        insertUser("INVENTORY", false);

        assertThat(store().initializeAdministrator(admin(), audit("corr-others"))).extracting(InitialAdminResult::created).isEqualTo(true);

        assertThat(admins()).isEqualTo(1);
        assertThat(users()).isEqualTo(3);
        assertThat(initializationAudits()).isEqualTo(1);
    }

    @Test
    void repeatingTheExecutionAfterASuccessfulOneChangesNothing() throws Exception {
        SystemUser created = admin("first@synkro.test", "$2a$12$first-hash");
        assertThat(store().initializeAdministrator(created, audit("corr-first"))).extracting(InitialAdminResult::created).isEqualTo(true);
        String before = text("SELECT user_id::text || '|' || password_hash FROM auth_schema.system_user");

        assertThat(store().initializeAdministrator(admin("second@synkro.test", "$2a$12$second-hash"), audit("corr-second")))
            .extracting(InitialAdminResult::created).isEqualTo(false);

        assertThat(users()).isEqualTo(1);
        assertThat(initializationAudits()).isEqualTo(1);
        assertThat(text("SELECT user_id::text || '|' || password_hash FROM auth_schema.system_user")).isEqualTo(before);
        assertThat(text("SELECT correlation_id FROM auth_schema.user_creation_audit")).isEqualTo("corr-first");
    }

    @Test
    void theCreatedAdministratorAndItsAuditCarryTheAgreedValues() throws Exception {
        SystemUser created = admin("ada@synkro.test", "$2a$12$stored-hash");
        InitializationAudit audit = audit("corr-values");

        assertThat(store().initializeAdministrator(created, audit)).extracting(InitialAdminResult::created).isEqualTo(true);

        assertThat(text("SELECT role || '|' || active || '|' || name || '|' || email || '|' || password_hash "
            + "FROM auth_schema.system_user WHERE user_id = ?::uuid", created.getUserId()))
            .isEqualTo("ADMIN|true|Ada Admin|ada@synkro.test|$2a$12$stored-hash");
        assertThat(text("SELECT operation || '|' || actor_kind || '|' || coalesce(actor_user_id::text, 'null') || '|' "
            + "|| operator_identity || '|' || created_user_id::text || '|' || outcome || '|' || correlation_id "
            + "FROM auth_schema.user_creation_audit WHERE audit_id = ?::uuid", audit.auditId()))
            .isEqualTo("INITIAL_ADMIN_CREATED|OPERATOR|null|" + OPERATOR + "|" + created.getUserId() + "|SUCCESS|corr-values");
        assertThat(text("SELECT (occurred_at = ?::timestamptz)::text FROM auth_schema.user_creation_audit", audit.occurredAt().toString()))
            .isEqualTo("true");
    }

    @Test
    void preexistingUsersAreNeverGivenFabricatedAuthorship() throws Exception {
        insertUser("SALESPERSON", true);

        store().initializeAdministrator(admin(), audit("corr-authorship"));

        assertThat(audits()).as("only the administrator created by the command has a record").isEqualTo(1);
    }

    @Test
    void theServiceRoleCanReadAndAppendAuditRecordsButNeverChangeOrRemoveThem() throws Exception {
        store().initializeAdministrator(admin(), audit("corr-privileges"));

        try (Connection c = appConnection(); Statement s = c.createStatement()) {
            assertThatThrownBy(() -> s.execute("UPDATE auth_schema.user_creation_audit SET correlation_id = 'x'"))
                .isInstanceOfSatisfying(SQLException.class, e -> assertThat(e.getSQLState()).isEqualTo("42501"));
            assertThatThrownBy(() -> s.execute("DELETE FROM auth_schema.user_creation_audit"))
                .isInstanceOfSatisfying(SQLException.class, e -> assertThat(e.getSQLState()).isEqualTo("42501"));
            assertThatThrownBy(() -> s.execute("TRUNCATE auth_schema.user_creation_audit"))
                .isInstanceOfSatisfying(SQLException.class, e -> assertThat(e.getSQLState()).isEqualTo("42501"));
        }
        assertThat(initializationAudits()).isEqualTo(1);
    }

    // ── AUTH-INIT-03: rollback, retry and timeout ───────────────────────────

    @Test
    void anAuditWriteFailureAfterTheUserInsertRollsBothBackAndALaterRetrySucceeds() throws Exception {
        // A real failure at the audit insert: its audit_id already belongs to another record.
        String actor = insertUser("SALESPERSON", true);
        String other = insertUser("SALESPERSON", true);
        UUID takenAuditId = UUID.randomUUID();
        try (Connection c = appConnection(); PreparedStatement s = c.prepareStatement(
            "INSERT INTO auth_schema.user_creation_audit (audit_id, operation, actor_kind, actor_user_id, created_user_id, "
                + "outcome, occurred_at, correlation_id) VALUES (?, 'USER_REGISTERED', 'ADMIN', ?::uuid, ?::uuid, 'SUCCESS', now(), 'seed')")) {
            s.setObject(1, takenAuditId);
            s.setString(2, actor);
            s.setString(3, other);
            s.executeUpdate();
        }
        SystemUser doomed = admin();

        assertThatThrownBy(() -> store().initializeAdministrator(doomed,
            new InitializationAudit(takenAuditId.toString(), OPERATOR, Instant.now().truncatedTo(ChronoUnit.MICROS), "corr-doomed")))
            .isInstanceOfSatisfying(InitializationFailedException.class, e -> {
                assertThat(e.kind()).isEqualTo(Kind.DATABASE);
                assertThat(e.sqlState()).isEqualTo("23505");
                assertThat(e.getMessage()).doesNotContain("audit_id").doesNotContain(takenAuditId.toString());
                assertThat(e.getCause()).isNull();
            });

        assertThat(count("SELECT count(*) FROM auth_schema.system_user WHERE user_id = ?::uuid", doomed.getUserId()))
            .as("the user insert was rolled back with the audit").isZero();
        assertThat(admins()).isZero();
        assertThat(initializationAudits()).isZero();
        assertThat(lockEntries(true)).as("the lock is released after rollback").isZero();

        assertThat(store().initializeAdministrator(admin(), audit("corr-retry"))).extracting(InitialAdminResult::created).isEqualTo(true);
        assertThat(admins()).isEqualTo(1);
        assertThat(initializationAudits()).isEqualTo(1);
    }

    @Test
    void anEmailAlreadyUsedByAnotherUserIsABusinessRuleAndLeavesNothingBehind() throws Exception {
        insertUser("SALESPERSON", true, "taken@synkro.test", "$2a$12$x");

        assertThatThrownBy(() -> store().initializeAdministrator(admin("taken@synkro.test", "$2a$12$y"), audit("corr-email")))
            .isInstanceOfSatisfying(BusinessRuleViolationException.class, e -> assertThat(e.getMessage()).contains("email"));

        assertThat(admins()).isZero();
        assertThat(audits()).isZero();
        assertThat(store().initializeAdministrator(admin("other@synkro.test", "$2a$12$y"), audit("corr-email-retry")))
            .extracting(InitialAdminResult::created).isEqualTo(true);
    }

    @Test
    void aLockHeldBeyondTheWaitMakesTheExecutionFailWithoutWritingAnything() throws Exception {
        try (Connection holder = appConnection()) {
            holder.setAutoCommit(false);
            try (Statement s = holder.createStatement()) {
                s.execute("SELECT pg_advisory_xact_lock(" + LOCK_KEY + "::bigint)");
            }
            long started = System.nanoTime();

            assertThatThrownBy(() -> store().initializeAdministrator(admin(), audit("corr-timeout")))
                .isInstanceOfSatisfying(InitializationFailedException.class, e -> {
                    assertThat(e.kind()).isEqualTo(Kind.LOCK_TIMEOUT);
                    assertThat(e.sqlState()).isEqualTo("55P03");
                    assertThat(e.getCause()).isNull();
                });

            Duration waited = Duration.ofNanos(System.nanoTime() - started);
            // Ten seconds of waiting, with generous bounds for connection setup and a loaded machine.
            assertThat(waited).isBetween(Duration.ofSeconds(9), Duration.ofSeconds(40));
            // The holder never released: no unlocked fallback wrote anything.
            assertThat(users()).isZero();
            assertThat(audits()).isZero();
            assertThat(lockEntries(false)).as("the timed-out execution left the queue").isZero();
            holder.rollback();
        }

        assertThat(lockEntries(true)).as("the holder released the lock").isZero();
        assertThat(store().initializeAdministrator(admin(), audit("corr-after-timeout"))).extracting(InitialAdminResult::created).isEqualTo(true);
        assertThat(admins()).isEqualTo(1);
        assertThat(initializationAudits()).isEqualTo(1);
        assertThat(lockEntries(true) + lockEntries(false)).isZero();
    }

    @Test
    void aRepeatInvocationAfterACommittedCreationIsANoOpEvenIfTheFirstResultWasLost() throws Exception {
        // Models "commit confirmation lost": the first run committed, the caller never learned it.
        store().initializeAdministrator(admin("committed@synkro.test", "$2a$12$committed"), audit("corr-lost"));

        assertThat(store().initializeAdministrator(admin("retry@synkro.test", "$2a$12$retry"), audit("corr-retry")))
            .extracting(InitialAdminResult::created).isEqualTo(false);
        assertThat(users()).isEqualTo(1);
        assertThat(text("SELECT email FROM auth_schema.system_user")).isEqualTo("committed@synkro.test");
    }

    // ── helpers ─────────────────────────────────────────────────────────────

    private static String scalar(Connection connection, String sql) throws SQLException {
        try (Statement s = connection.createStatement(); ResultSet rs = s.executeQuery(sql)) {
            rs.next();
            return rs.getString(1);
        }
    }

    private static boolean awaitQuietly(CountDownLatch latch) {
        try {
            return latch.await(30, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    private interface Condition {
        boolean holds() throws Exception;
    }

    private static void awaitUntil(Condition condition, String description) throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(20).toNanos();
        while (System.nanoTime() < deadline) {
            if (condition.holds()) {
                return;
            }
            Thread.sleep(50);
        }
        throw new AssertionError("Timed out waiting for " + description);
    }
}
