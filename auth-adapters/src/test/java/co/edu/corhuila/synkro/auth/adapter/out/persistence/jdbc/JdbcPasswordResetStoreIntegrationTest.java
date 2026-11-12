package co.edu.corhuila.synkro.auth.adapter.out.persistence.jdbc;

import co.edu.corhuila.synkro.auth.application.port.out.PasswordResetStore.Outcome;
import co.edu.corhuila.synkro.auth.application.port.out.PasswordResetStore.Recorded;
import co.edu.corhuila.synkro.auth.application.port.out.PasswordResetStore.RequestReceipt;
import co.edu.corhuila.synkro.auth.application.port.out.PasswordResetStore.ResetAttribution;
import co.edu.corhuila.synkro.auth.application.port.out.RefreshTokenStore.Consumption;
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
 * The new hash, the revocation of the target's refresh credentials, the audit record and the key are one unit on one
 * connection, checked on the real auth_schema as auth_app (HU-AUTH-19, ADR-021 Decisions 3 to 5). Rows are never
 * deleted: every test uses fresh users and keys.
 */
@EnabledIfEnvironmentVariable(named = PostgresTestDatabase.URL_VARIABLE, matches = ".+")
class JdbcPasswordResetStoreIntegrationTest {

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
        return "it-reset-" + UUID.randomUUID();
    }

    // The receipt table accepts only bcrypt strings, so a hash handed straight to the store must have that shape.
    private static String newHash() {
        return PostgresTestDatabase.bcryptShaped();
    }

    private String target(String role, boolean active) {
        return PostgresTestDatabase.insertUser(jdbc, "Target", PostgresTestDatabase.uniqueEmail(), OLD_HASH, role, active);
    }

    private static ResetAttribution attribution(String actor) {
        return new ResetAttribution(UUID.randomUUID().toString(), actor, Instant.now().truncatedTo(ChronoUnit.MICROS), "corr-" + UUID.randomUUID());
    }

    private Outcome reset(String key, String targetId, String hash) {
        return store.resetPasswordWithAudit(key, targetId, hash, attribution(actorId));
    }

    private String hashOf(String userId) {
        return jdbc.queryForObject("SELECT password_hash FROM auth_schema.system_user WHERE user_id = ?::uuid", String.class, userId);
    }

    private int activeRefreshTokens(String userId) {
        return jdbc.queryForObject("SELECT count(*) FROM auth_schema.refresh_token WHERE user_id = ?::uuid AND active", Integer.class, userId);
    }

    private int auditRowsOf(String targetId) {
        return jdbc.queryForObject("SELECT count(*) FROM auth_schema.password_reset_audit WHERE target_user_id = ?::uuid", Integer.class, targetId);
    }

    private int auditRowsFor(String actor, String key) {
        return jdbc.queryForObject("SELECT count(*) FROM auth_schema.password_reset_audit WHERE actor_user_id = ?::uuid AND idempotency_key = ?",
            Integer.class, actor, key);
    }

    private String issueRefreshToken(String userId) {
        String tokenHash = "refresh-" + UUID.randomUUID();
        refreshTokens.save(tokenHash, userId, Instant.now().plus(7, ChronoUnit.DAYS));
        return tokenHash;
    }

    // ── the unit ─────────────────────────────────────────────────────

    @Test
    @Tag("AUTH-RESET-01")
    void aReset_replacesTheHash_revokesTheTargetsRefreshTokens_andRecordsTheAuditAndKey() {
        String targetId = target("SALESPERSON", true);
        issueRefreshToken(targetId);
        issueRefreshToken(targetId);
        String key = newKey();
        String hash = newHash();
        ResetAttribution attribution = attribution(actorId);

        Outcome outcome = store.resetPasswordWithAudit(key, targetId, hash, attribution);

        assertThat(outcome).isInstanceOfSatisfying(Outcome.Reset.class, r -> assertThat(r.occurredAt()).isEqualTo(attribution.occurredAt()));
        assertThat(hashOf(targetId)).isEqualTo(hash);
        assertThat(activeRefreshTokens(targetId)).isZero();
        Map<String, Object> row = jdbc.queryForMap(
            "SELECT audit_id::text AS audit_id, operation, actor_user_id::text AS actor, target_user_id::text AS target, "
                + "idempotency_key, outcome, occurred_at, correlation_id FROM auth_schema.password_reset_audit "
                + "WHERE actor_user_id = ?::uuid AND idempotency_key = ?", actorId, key);
        assertThat(row.get("audit_id")).isEqualTo(attribution.auditId());
        assertThat(row.get("operation")).isEqualTo("PASSWORD_RESET");
        assertThat(row.get("actor")).isEqualTo(actorId);
        assertThat(row.get("target")).isEqualTo(targetId);
        assertThat(row.get("outcome")).isEqualTo("SUCCESS");
        assertThat(((java.sql.Timestamp) row.get("occurred_at")).toInstant()).isEqualTo(attribution.occurredAt());
        assertThat(row.get("correlation_id")).isEqualTo(attribution.correlationId());
    }

    @Test
    void anInventoryUserIsResetToo() {
        String targetId = target("INVENTORY", true);

        String hash = newHash();

        assertThat(reset(newKey(), targetId, hash)).isInstanceOf(Outcome.Reset.class);

        assertThat(hashOf(targetId)).isEqualTo(hash);
    }

    @Test
    void theAuditRowHoldsNoHashAndNoPassword() {
        String targetId = target("SALESPERSON", true);
        String key = newKey();
        String hash = newHash();

        reset(key, targetId, hash);

        String everything = jdbc.queryForObject("SELECT row(a.*)::text FROM auth_schema.password_reset_audit a "
            + "WHERE a.actor_user_id = ?::uuid AND a.idempotency_key = ?", String.class, actorId, key);
        assertThat(everything).doesNotContain(hash).doesNotContain(OLD_HASH);
    }

    @Test
    void otherUsersAndTheirSessionsAreUntouched() {
        String targetId = target("SALESPERSON", true);
        String bystanderId = target("SALESPERSON", true);
        issueRefreshToken(targetId);
        issueRefreshToken(bystanderId);

        reset(newKey(), targetId, newHash());

        assertThat(hashOf(bystanderId)).isEqualTo(OLD_HASH);
        assertThat(activeRefreshTokens(bystanderId)).isEqualTo(1);
        assertThat(auditRowsOf(bystanderId)).isZero();
    }

    @Test
    void theRevokedRowsAreKeptAsUsed_nothingIsDeleted() {
        String targetId = target("SALESPERSON", true);
        String tokenHash = issueRefreshToken(targetId);

        reset(newKey(), targetId, newHash());

        assertThat(jdbc.queryForObject("SELECT count(*) FROM auth_schema.refresh_token WHERE token = ?", Integer.class, tokenHash)).isEqualTo(1);
        assertThat(refreshTokens.consume(tokenHash)).isInstanceOf(Consumption.AlreadyUsed.class);
    }

    // ── eligibility inside the unit ──────────────────────────────────

    @Test
    void anAdminTarget_isNotEligible_andNothingIsKept_notEvenTheKey() {
        String adminTarget = target("ADMIN", true);
        issueRefreshToken(adminTarget);
        String key = newKey();

        assertThat(reset(key, adminTarget, newHash())).isInstanceOf(Outcome.TargetNotEligible.class);

        assertThat(hashOf(adminTarget)).isEqualTo(OLD_HASH);
        assertThat(activeRefreshTokens(adminTarget)).isEqualTo(1);
        assertThat(auditRowsFor(actorId, key)).isZero();
        String salesId = target("SALESPERSON", true);
        assertThat(reset(key, salesId, newHash())).as("the key was not consumed").isInstanceOf(Outcome.Reset.class);
    }

    @Test
    void aTargetThatCannotBeResetBecauseItIsInactive_changesNothing() {
        String inactive = target("SALESPERSON", false);
        issueRefreshToken(inactive);
        String key = newKey();

        assertThat(reset(key, inactive, newHash())).isInstanceOf(Outcome.TargetNotEligible.class);

        assertThat(hashOf(inactive)).isEqualTo(OLD_HASH);
        assertThat(activeRefreshTokens(inactive)).isEqualTo(1);
        assertThat(auditRowsFor(actorId, key)).isZero();
    }

    @Test
    void aTargetThatDoesNotExist_isNotEligible_andLeavesNoKey() {
        String key = newKey();

        assertThat(reset(key, UUID.randomUUID().toString(), newHash())).isInstanceOf(Outcome.TargetNotEligible.class);

        assertThat(auditRowsFor(actorId, key)).isZero();
    }

    // ── the key ──────────────────────────────────────────────────────

    @Test
    void theKeyIsFoundByItsActorOnly() {
        String targetId = target("SALESPERSON", true);
        String key = newKey();
        ResetAttribution attribution = attribution(actorId);
        String hash = newHash();
        store.resetPasswordWithAudit(key, targetId, hash, attribution);
        String otherAdmin = PostgresTestDatabase.insertUser(jdbc, "ADMIN", true);

        assertThat(store.findByActorAndKey(actorId, key)).contains(new Recorded(targetId, attribution.occurredAt(),
            java.util.Optional.of(new RequestReceipt(hash))));
        assertThat(store.findByActorAndKey(otherAdmin, key)).isEmpty();
        assertThat(store.findByActorAndKey(actorId, newKey())).isEmpty();
    }

    @Test
    void theSameKeyForTheSameActor_isAlreadyRecorded_andChangesNothingNew() {
        String targetId = target("SALESPERSON", true);
        String key = newKey();
        String firstHash = newHash();
        reset(key, targetId, firstHash);
        // The target signs in again after the reset: a replay must not end that session.
        issueRefreshToken(targetId);

        Outcome again = reset(key, targetId, newHash());

        assertThat(again).isInstanceOfSatisfying(Outcome.AlreadyRecorded.class, a -> assertThat(a.record().targetUserId()).isEqualTo(targetId));
        assertThat(hashOf(targetId)).isEqualTo(firstHash);
        assertThat(activeRefreshTokens(targetId)).as("the session opened after the reset survives the replay").isEqualTo(1);
        assertThat(auditRowsFor(actorId, key)).isEqualTo(1);
    }

    @Test
    void theSameKeyUnderAnotherActor_isAnotherKey() {
        String targetId = target("SALESPERSON", true);
        String otherTarget = target("INVENTORY", true);
        String otherAdmin = PostgresTestDatabase.insertUser(jdbc, "ADMIN", true);
        String key = newKey();

        Outcome mine = store.resetPasswordWithAudit(key, targetId, newHash(), attribution(actorId));
        Outcome theirs = store.resetPasswordWithAudit(key, otherTarget, newHash(), attribution(otherAdmin));

        assertThat(mine).isInstanceOf(Outcome.Reset.class);
        assertThat(theirs).isInstanceOf(Outcome.Reset.class);
        assertThat(auditRowsFor(actorId, key)).isEqualTo(1);
        assertThat(auditRowsFor(otherAdmin, key)).isEqualTo(1);
    }

    // ── atomicity: a failure after some of the writes undoes all of them ─────────

    private void withFailingTrigger(String table, String targetId, Runnable action) throws SQLException {
        InitializationTestDatabase.requireDisposableDatabase();
        String suffix = UUID.randomUUID().toString().replace("-", "");
        String function = "auth_schema.it_fail_" + suffix;
        try (Connection c = InitializationTestDatabase.adminConnection(); Statement s = c.createStatement()) {
            DisposableDatabaseGuard.requireDatabase(c, System.getenv(DisposableDatabaseGuard.NAME_VARIABLE));
            // Both tables carry the owner in user_id, so one trigger body serves them: it fails for this target only.
            s.execute("CREATE FUNCTION " + function + "() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN "
                + "IF NEW.user_id = '" + targetId + "'::uuid THEN RAISE EXCEPTION 'injected failure'; END IF; RETURN NEW; END $$");
            s.execute("CREATE TRIGGER it_fail_" + suffix + " BEFORE UPDATE ON " + table + " FOR EACH ROW EXECUTE FUNCTION " + function + "()");
            try {
                action.run();
            } finally {
                s.execute("DROP TRIGGER it_fail_" + suffix + " ON " + table);
                s.execute("DROP FUNCTION " + function + "()");
            }
        }
    }

    @Test
    @Tag("AUTH-RESET-02")
    void ifTheRevocationFails_theNewHashTheAuditAndTheKeyAreRolledBack() throws SQLException {
        String targetId = target("SALESPERSON", true);
        issueRefreshToken(targetId);
        String key = newKey();

        withFailingTrigger("auth_schema.refresh_token", targetId, () ->
            assertThatThrownBy(() -> reset(key, targetId, newHash())).isInstanceOf(DataAccessException.class));

        assertThat(hashOf(targetId)).as("no new password").isEqualTo(OLD_HASH);
        assertThat(activeRefreshTokens(targetId)).as("no revocation").isEqualTo(1);
        assertThat(auditRowsFor(actorId, key)).as("no audit row, so no key").isZero();
        assertThat(reset(key, targetId, newHash())).as("the key can be used again").isInstanceOf(Outcome.Reset.class);
    }

    @Test
    void ifThePasswordUpdateFails_theAuditAndTheKeyAreRolledBack() throws SQLException {
        String targetId = target("SALESPERSON", true);
        issueRefreshToken(targetId);
        String key = newKey();

        withFailingTrigger("auth_schema.system_user", targetId, () ->
            assertThatThrownBy(() -> reset(key, targetId, newHash())).isInstanceOf(DataAccessException.class));

        assertThat(hashOf(targetId)).isEqualTo(OLD_HASH);
        assertThat(activeRefreshTokens(targetId)).isEqualTo(1);
        assertThat(auditRowsFor(actorId, key)).isZero();
    }

    @Test
    void ifTheAuditCannotBeWritten_nothingIsChanged() {
        String targetId = target("SALESPERSON", true);
        issueRefreshToken(targetId);
        String key = newKey();
        ResetAttribution withoutCorrelation = new ResetAttribution(UUID.randomUUID().toString(), actorId,
            Instant.now().truncatedTo(ChronoUnit.MICROS), "");

        assertThatThrownBy(() -> store.resetPasswordWithAudit(key, targetId, newHash(), withoutCorrelation))
            .isInstanceOf(DataAccessException.class);

        assertThat(hashOf(targetId)).isEqualTo(OLD_HASH);
        assertThat(activeRefreshTokens(targetId)).isEqualTo(1);
        assertThat(auditRowsFor(actorId, key)).isZero();
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
    @Tag("AUTH-RESET-03")
    void twoSimultaneousRequestsWithTheSameKey_executeOnce_andTheOtherSeesTheRecord() throws Exception {
        for (int round = 0; round < 8; round++) {
            String targetId = target("SALESPERSON", true);
            issueRefreshToken(targetId);
            String key = newKey();
            String hashA = newHash();
            String hashB = newHash();

            List<Object> outcomes = runTogether(List.of(
                () -> reset(key, targetId, hashA),
                () -> reset(key, targetId, hashB)));

            assertThat(outcomes).filteredOn(o -> o instanceof Outcome.Reset).hasSize(1);
            assertThat(outcomes).filteredOn(o -> o instanceof Outcome.AlreadyRecorded).hasSize(1);
            assertThat(auditRowsFor(actorId, key)).isEqualTo(1);
            assertThat(hashOf(targetId)).isIn(hashA, hashB);
            assertThat(activeRefreshTokens(targetId)).isZero();
        }
    }

    @Test
    void twoSimultaneousRequestsWithDifferentKeys_areBothAudited_andTheLastCommitDefinesThePassword() throws Exception {
        for (int round = 0; round < 5; round++) {
            String targetId = target("SALESPERSON", true);
            String keyA = newKey();
            String keyB = newKey();
            String hashA = newHash();
            String hashB = newHash();

            List<Object> outcomes = runTogether(List.of(
                () -> reset(keyA, targetId, hashA),
                () -> reset(keyB, targetId, hashB)));

            assertThat(outcomes).allSatisfy(o -> assertThat(o).isInstanceOf(Outcome.Reset.class));
            assertThat(auditRowsOf(targetId)).isEqualTo(2);
            assertThat(hashOf(targetId)).isIn(hashA, hashB);
        }
    }

    @Test
    void aResetAndARotationOfTheSameOwner_neverLeaveAUsableCredential() throws Exception {
        for (int round = 0; round < 8; round++) {
            String targetId = target("SALESPERSON", true);
            String oldToken = issueRefreshToken(targetId);
            String replacement = "refresh-replacement-" + UUID.randomUUID();

            runTogether(List.of(
                () -> reset(newKey(), targetId, newHash()),
                () -> refreshTokens.rotate(oldToken, replacement, Instant.now().plus(7, ChronoUnit.DAYS))));

            assertThat(activeRefreshTokens(targetId))
                .as("a rotation that won the race left a replacement that the reset then revoked, or lost and stored nothing")
                .isZero();
        }
    }

    // ── grants ───────────────────────────────────────────────────────

    @Test
    void theServiceLoginCanInsertAndReadTheAuditButNeverChangeOrDeleteIt() {
        String targetId = target("SALESPERSON", true);
        String key = newKey();
        reset(key, targetId, newHash());

        assertThatThrownBy(() -> jdbc.update("UPDATE auth_schema.password_reset_audit SET correlation_id = 'x' WHERE idempotency_key = ?", key))
            .isInstanceOf(DataAccessException.class);
        assertThatThrownBy(() -> jdbc.update("DELETE FROM auth_schema.password_reset_audit WHERE idempotency_key = ?", key))
            .isInstanceOf(DataAccessException.class);
        assertThat(auditRowsFor(actorId, key)).isEqualTo(1);
    }
}
