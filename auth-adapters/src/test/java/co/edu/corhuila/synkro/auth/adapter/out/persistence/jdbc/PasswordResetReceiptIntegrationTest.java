package co.edu.corhuila.synkro.auth.adapter.out.persistence.jdbc;

import co.edu.corhuila.synkro.auth.application.port.out.PasswordResetStore.Outcome;
import co.edu.corhuila.synkro.auth.application.port.out.PasswordResetStore.Recorded;
import co.edu.corhuila.synkro.auth.application.port.out.PasswordResetStore.RequestReceipt;
import co.edu.corhuila.synkro.auth.application.port.out.PasswordResetStore.ResetAttribution;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The private receipt of ADR-021 Decision 2 on the real auth_schema: what it stores, when it stops being usable, what
 * the cleanup may take away, who may touch it, and that its failure undoes the whole reset. Tests that need the
 * administrator (to move the clock of a row, to run the cleanup, to inject a failure) are guarded by the disposable
 * database opt-in. No assertion prints a hash: they compare equality and counts.
 */
@EnabledIfEnvironmentVariable(named = PostgresTestDatabase.URL_VARIABLE, matches = ".+")
class PasswordResetReceiptIntegrationTest {

    private static final String OLD_HASH = "old-hash-value";

    private JdbcTemplate jdbc;
    private JdbcPasswordResetStore store;
    private JdbcRefreshTokenStore refreshTokens;
    private String actorId;

    @BeforeEach
    void setUp() {
        jdbc = PostgresTestDatabase.jdbcTemplate();
        store = new JdbcPasswordResetStore(jdbc, PostgresTestDatabase.transactions(jdbc));
        refreshTokens = new JdbcRefreshTokenStore(jdbc, PostgresTestDatabase.transactionManager(jdbc));
        actorId = PostgresTestDatabase.insertUser(jdbc, "ADMIN", true);
    }

    private static String newKey() {
        return "it-receipt-" + UUID.randomUUID();
    }

    private String target() {
        return PostgresTestDatabase.insertUser(jdbc, "Target", PostgresTestDatabase.uniqueEmail(), OLD_HASH, "SALESPERSON", true);
    }

    private static ResetAttribution attribution(String actor) {
        return new ResetAttribution(UUID.randomUUID().toString(), actor, Instant.now().truncatedTo(ChronoUnit.MICROS), "corr-" + UUID.randomUUID());
    }

    private Outcome reset(String key, String targetId, String hash) {
        return store.resetPasswordWithAudit(key, targetId, hash, attribution(actorId));
    }

    private Connection admin() throws SQLException {
        InitializationTestDatabase.requireDisposableDatabase();
        Connection c = InitializationTestDatabase.adminConnection();
        try {
            DisposableDatabaseGuard.requireDatabase(c, System.getenv(DisposableDatabaseGuard.NAME_VARIABLE));
        } catch (RuntimeException | Error e) {
            c.close();
            throw e;
        }
        return c;
    }

    private int receiptsOf(String key) {
        return jdbc.queryForObject("SELECT count(*) FROM auth_schema.password_reset_receipt r JOIN auth_schema.password_reset_audit a "
            + "ON a.audit_id = r.audit_id WHERE a.actor_user_id = ?::uuid AND a.idempotency_key = ?", Integer.class, actorId, key);
    }

    private int auditsOf(String key) {
        return jdbc.queryForObject("SELECT count(*) FROM auth_schema.password_reset_audit WHERE actor_user_id = ?::uuid AND idempotency_key = ?",
            Integer.class, actorId, key);
    }

    private String hashOf(String userId) {
        return jdbc.queryForObject("SELECT password_hash FROM auth_schema.system_user WHERE user_id = ?::uuid", String.class, userId);
    }

    private int activeRefreshTokens(String userId) {
        return jdbc.queryForObject("SELECT count(*) FROM auth_schema.refresh_token WHERE user_id = ?::uuid AND active", Integer.class, userId);
    }

    private void expireReceiptOf(String key) throws SQLException {
        try (Connection c = admin(); Statement s = c.createStatement()) {
            s.executeUpdate("UPDATE auth_schema.password_reset_receipt SET expires_at = clock_timestamp() - interval '1 second' "
                + "WHERE audit_id = (SELECT audit_id FROM auth_schema.password_reset_audit WHERE actor_user_id = '" + actorId
                + "'::uuid AND idempotency_key = '" + key + "')");
        }
    }

    // ── what the receipt keeps ───────────────────────────────────────

    @Test
    @Tag("AUTH-RESET-RECEIPT-01")
    void theReceiptKeepsTheBcryptOfThatResetAndNothingElse_andItExpiresIn24HoursByTheDatabaseClock() {
        String targetId = target();
        String key = newKey();
        String hash = PostgresTestDatabase.bcryptShaped();

        reset(key, targetId, hash);

        assertThat(receiptsOf(key)).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT r.request_password_hash = ? FROM auth_schema.password_reset_receipt r JOIN "
            + "auth_schema.password_reset_audit a ON a.audit_id = r.audit_id WHERE a.actor_user_id = ?::uuid AND a.idempotency_key = ?",
            Boolean.class, hash, actorId, key)).as("the receipt holds the exact bcrypt string assigned").isTrue();
        Double secondsLeft = jdbc.queryForObject("SELECT extract(epoch FROM (r.expires_at - clock_timestamp())) FROM "
            + "auth_schema.password_reset_receipt r JOIN auth_schema.password_reset_audit a ON a.audit_id = r.audit_id "
            + "WHERE a.actor_user_id = ?::uuid AND a.idempotency_key = ?", Double.class, actorId, key);
        assertThat(secondsLeft).isBetween(24 * 3600 - 60.0, 24 * 3600.0);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM information_schema.columns WHERE table_schema = 'auth_schema' "
            + "AND table_name = 'password_reset_receipt'", Integer.class)).as("audit_id, hash and expiry: no password, no body").isEqualTo(3);
    }

    @Test
    @Tag("AUTH-RESET-RECEIPT-01")
    void aRecordedKeyAnswersWithTheReceipt_whileItIsValid() {
        String targetId = target();
        String key = newKey();
        String hash = PostgresTestDatabase.bcryptShaped();
        ResetAttribution attribution = attribution(actorId);
        store.resetPasswordWithAudit(key, targetId, hash, attribution);

        assertThat(store.findByActorAndKey(actorId, key))
            .contains(new Recorded(targetId, attribution.occurredAt(), Optional.of(new RequestReceipt(hash))));
        assertThat(reset(key, targetId, PostgresTestDatabase.bcryptShaped()))
            .as("the retry's own attempt finds the key taken").isInstanceOfSatisfying(Outcome.AlreadyRecorded.class,
                raced -> assertThat(raced.record().receipt()).contains(new RequestReceipt(hash)));
    }

    // ── expiry is logical; the key stays consumed ───────────────────

    @Test
    @Tag("AUTH-RESET-RECEIPT-02")
    void anExpiredReceiptIsNotReturned_butTheKeyStaysConsumed_andNothingReExecutes() throws Exception {
        String targetId = target();
        String key = newKey();
        String hash = PostgresTestDatabase.bcryptShaped();
        reset(key, targetId, hash);
        String hashAfterTheReset = hashOf(targetId);
        expireReceiptOf(key);

        Optional<Recorded> found = store.findByActorAndKey(actorId, key);

        assertThat(found).isPresent();
        assertThat(found.get().receipt()).as("logically expired: decided at lookup by the database clock").isEmpty();
        assertThat(receiptsOf(key)).as("the row is still there until the cleanup runs").isEqualTo(1);
        assertThat(reset(key, targetId, PostgresTestDatabase.bcryptShaped())).isInstanceOf(Outcome.AlreadyRecorded.class);
        assertThat(hashOf(targetId)).as("no new effect").isEqualTo(hashAfterTheReset);
    }

    // ── cleanup: bounded, only expired receipts, audits and keys stay ─

    @Test
    @Tag("AUTH-RESET-RECEIPT-03")
    void theCleanupDeletesOnlyExpiredReceipts_andKeepsTheAuditsAndTheConsumedKeys() throws Exception {
        String targetId = target();
        String expiredKey = newKey();
        String liveKey = newKey();
        reset(expiredKey, targetId, PostgresTestDatabase.bcryptShaped());
        reset(liveKey, targetId, PostgresTestDatabase.bcryptShaped());
        expireReceiptOf(expiredKey);

        int deleted;
        try (Connection c = admin(); Statement s = c.createStatement()) {
            // Other tests leave expired receipts behind, so a batch large enough to take them all is the bounded call.
            var rs = s.executeQuery("SELECT auth_schema.purge_expired_password_reset_receipts(10000)");
            rs.next();
            deleted = rs.getInt(1);
        }

        assertThat(deleted).isGreaterThanOrEqualTo(1);
        assertThat(receiptsOf(expiredKey)).isZero();
        assertThat(receiptsOf(liveKey)).as("a valid receipt is never taken").isEqualTo(1);
        assertThat(auditsOf(expiredKey)).as("the audit of the expired one stays").isEqualTo(1);
        assertThat(reset(expiredKey, targetId, PostgresTestDatabase.bcryptShaped()))
            .as("and so does the consumed key: the cleanup never frees it").isInstanceOf(Outcome.AlreadyRecorded.class);
        assertThat(store.findByActorAndKey(actorId, expiredKey).orElseThrow().receipt()).isEmpty();
    }

    @Test
    @Tag("AUTH-RESET-RECEIPT-03")
    void aResetThatRacesAnUncommittedCleanupDoesNotExecuteAgain() throws Exception {
        String targetId = target();
        String key = newKey();
        reset(key, targetId, PostgresTestDatabase.bcryptShaped());
        String hashAfterTheReset = hashOf(targetId);
        expireReceiptOf(key);
        ExecutorService pool = Executors.newSingleThreadExecutor();
        try (Connection c = admin()) {
            c.setAutoCommit(false);
            try (Statement s = c.createStatement()) {
                s.execute("SELECT auth_schema.purge_expired_password_reset_receipts(10000)");
            }
            // The cleanup has deleted the receipt in a transaction that has not committed.
            Future<Outcome> racing = pool.submit(() -> reset(key, targetId, PostgresTestDatabase.bcryptShaped()));
            assertThat(racing.get(30, TimeUnit.SECONDS)).isInstanceOf(Outcome.AlreadyRecorded.class);
            c.commit();
        } finally {
            pool.shutdownNow();
        }

        assertThat(hashOf(targetId)).as("no second reset, before or after the cleanup commits").isEqualTo(hashAfterTheReset);
        assertThat(reset(key, targetId, PostgresTestDatabase.bcryptShaped())).isInstanceOf(Outcome.AlreadyRecorded.class);
        assertThat(auditsOf(key)).isEqualTo(1);
    }

    @Test
    @Tag("AUTH-RESET-RECEIPT-03")
    void theCleanupRefusesABatchOutsideItsBounds() throws Exception {
        try (Connection c = admin(); Statement s = c.createStatement()) {
            assertThatThrownBy(() -> s.execute("SELECT auth_schema.purge_expired_password_reset_receipts(0)"))
                .isInstanceOf(SQLException.class).hasMessageContaining("batch_size");
        }
        try (Connection c = admin(); Statement s = c.createStatement()) {
            assertThatThrownBy(() -> s.execute("SELECT auth_schema.purge_expired_password_reset_receipts(10001)"))
                .isInstanceOf(SQLException.class).hasMessageContaining("batch_size");
        }
    }

    // ── atomicity: the receipt belongs to the unit ──────────────────

    @Test
    @Tag("AUTH-RESET-RECEIPT-04")
    void aFailureInsertingTheReceiptUndoesThePassword_theRevocation_theAuditAndTheKey() throws Exception {
        String targetId = target();
        refreshTokens.save("refresh-" + UUID.randomUUID(), targetId, Instant.now().plus(7, ChronoUnit.DAYS));
        String key = newKey();
        String hashBefore = hashOf(targetId);
        String trigger = "it_fail_receipt_" + UUID.randomUUID().toString().replace("-", "");
        try (Connection c = admin(); Statement s = c.createStatement()) {
            s.execute("CREATE FUNCTION auth_schema." + trigger + "() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN "
                + "RAISE EXCEPTION 'injected receipt failure'; END $$");
            s.execute("CREATE TRIGGER " + trigger + " BEFORE INSERT ON auth_schema.password_reset_receipt "
                + "FOR EACH ROW EXECUTE FUNCTION auth_schema." + trigger + "()");
        }
        try {
            assertThatThrownBy(() -> reset(key, targetId, PostgresTestDatabase.bcryptShaped())).isInstanceOf(DataAccessException.class);
        } finally {
            try (Connection c = admin(); Statement s = c.createStatement()) {
                s.execute("DROP TRIGGER " + trigger + " ON auth_schema.password_reset_receipt");
                s.execute("DROP FUNCTION auth_schema." + trigger + "()");
            }
        }

        assertThat(hashOf(targetId)).as("password unchanged").isEqualTo(hashBefore);
        assertThat(activeRefreshTokens(targetId)).as("sessions not revoked").isEqualTo(1);
        assertThat(auditsOf(key)).as("no audit row").isZero();
        assertThat(receiptsOf(key)).isZero();
        assertThat(reset(key, targetId, PostgresTestDatabase.bcryptShaped())).as("the key is free again").isInstanceOf(Outcome.Reset.class);
    }

    @Test
    @Tag("AUTH-RESET-RECEIPT-04")
    void aHashThatIsNotBcryptIsRefusedByTheReceipt_andTheWholeResetRollsBack() {
        String targetId = target();
        String key = newKey();
        String hashBefore = hashOf(targetId);

        assertThatThrownBy(() -> reset(key, targetId, "not-a-bcrypt-hash")).isInstanceOf(DataAccessException.class);

        assertThat(hashOf(targetId)).isEqualTo(hashBefore);
        assertThat(auditsOf(key)).isZero();
    }

    @Test
    @Tag("AUTH-RESET-RECEIPT-04")
    void anAuditFailureLeavesNoReceiptAndNoOtherEffect() {
        String targetId = target();
        String key = newKey();
        String hashBefore = hashOf(targetId);
        // A malformed correlation id is not a failure source here; an audit that cannot be inserted is: the actor is gone.
        ResetAttribution ghost = new ResetAttribution(UUID.randomUUID().toString(), UUID.randomUUID().toString(),
            Instant.now().truncatedTo(ChronoUnit.MICROS), "corr");

        assertThatThrownBy(() -> store.resetPasswordWithAudit(key, targetId, PostgresTestDatabase.bcryptShaped(), ghost))
            .isInstanceOf(DataAccessException.class);

        assertThat(hashOf(targetId)).isEqualTo(hashBefore);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM auth_schema.password_reset_receipt r JOIN auth_schema.password_reset_audit a "
            + "ON a.audit_id = r.audit_id WHERE a.target_user_id = ?::uuid", Integer.class, targetId)).isZero();
    }

    // ── permissions ──────────────────────────────────────────────────

    @Test
    @Tag("AUTH-RESET-RECEIPT-05")
    void theRuntimeRoleReadsAndInsertsReceiptsButCannotUpdateDeleteTruncateOrRunTheCleanup() {
        String targetId = target();
        String key = newKey();
        reset(key, targetId, PostgresTestDatabase.bcryptShaped());

        assertThat(receiptsOf(key)).as("SELECT and INSERT are what the service needs").isEqualTo(1);
        assertThatThrownBy(() -> jdbc.update("UPDATE auth_schema.password_reset_receipt SET expires_at = now()"))
            .rootCause().hasMessageContaining("permission denied");
        assertThatThrownBy(() -> jdbc.update("DELETE FROM auth_schema.password_reset_receipt"))
            .rootCause().hasMessageContaining("permission denied");
        assertThatThrownBy(() -> jdbc.execute("TRUNCATE auth_schema.password_reset_receipt"))
            .rootCause().hasMessageContaining("permission denied");
        assertThatThrownBy(() -> jdbc.queryForObject("SELECT auth_schema.purge_expired_password_reset_receipts(1)", Integer.class))
            .rootCause().hasMessageContaining("permission denied");
    }

    @Test
    @Tag("AUTH-RESET-RECEIPT-05")
    void aGeneralReaderCannotReadTheReceipts() throws Exception {
        try (Connection c = admin(); Statement s = c.createStatement()) {
            s.execute("SET ROLE auth_reader");
            assertThatThrownBy(() -> s.executeQuery("SELECT * FROM auth_schema.password_reset_receipt"))
                .isInstanceOf(SQLException.class).hasMessageContaining("permission denied");
            assertThatThrownBy(() -> s.executeQuery("SELECT request_password_hash FROM auth_schema.password_reset_receipt"))
                .isInstanceOf(SQLException.class).hasMessageContaining("permission denied");
        }
    }
}
