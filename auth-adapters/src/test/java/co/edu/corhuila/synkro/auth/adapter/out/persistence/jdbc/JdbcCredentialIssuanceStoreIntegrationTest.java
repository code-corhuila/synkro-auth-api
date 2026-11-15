package co.edu.corhuila.synkro.auth.adapter.out.persistence.jdbc;

import co.edu.corhuila.synkro.auth.domain.model.SystemUser;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.jdbc.core.JdbcTemplate;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The credential-issuance port on real PostgreSQL (ADR-021 Decision 3): the refresh credential is saved only if, under
 * the per-owner lock, the user is still active and still holds the hash that login verified. No assertion prints a hash.
 */
@EnabledIfEnvironmentVariable(named = PostgresTestDatabase.URL_VARIABLE, matches = ".+")
class JdbcCredentialIssuanceStoreIntegrationTest {

    private JdbcTemplate jdbc;
    private JdbcCredentialIssuanceStore store;
    private String userId;
    private String hash;
    private ExecutorService pool;
    private OwnerLockGate gate;

    @BeforeEach
    void setUp() {
        jdbc = PostgresTestDatabase.jdbcTemplate();
        store = new JdbcCredentialIssuanceStore(jdbc, PostgresTestDatabase.transactions(jdbc));
        hash = PostgresTestDatabase.bcryptShaped();
        userId = PostgresTestDatabase.insertUser(jdbc, "Holder", PostgresTestDatabase.uniqueEmail(), hash, "SALESPERSON", true);
        pool = Executors.newSingleThreadExecutor();
    }

    @AfterEach
    void tearDown() throws Exception {
        if (gate != null) {
            gate.close();
        }
        pool.shutdownNow();
    }

    private static Instant expiry() {
        return Instant.now().plus(7, ChronoUnit.DAYS);
    }

    private int refreshRows(String owner) {
        return jdbc.queryForObject("SELECT count(*) FROM auth_schema.refresh_token WHERE user_id = ?::uuid", Integer.class, owner);
    }

    @Test
    @Tag("AUTH-RESET-04")
    void savesTheCredential_andReturnsTheCurrentIdentity_whenTheHashIsTheVerifiedOne() {
        Optional<SystemUser> current = store.persistRefresh(userId, hash, "token-" + UUID.randomUUID(), expiry());

        assertThat(current).isPresent();
        assertThat(current.get().getUserId()).isEqualTo(userId);
        assertThat(current.get().getRole()).isEqualTo("SALESPERSON");
        assertThat(refreshRows(userId)).isEqualTo(1);
    }

    @Test
    @Tag("AUTH-RESET-04")
    void savesNothing_whenTheStoredHashIsNotTheVerifiedOne() {
        Optional<SystemUser> current = store.persistRefresh(userId, PostgresTestDatabase.bcryptShaped(), "token-" + UUID.randomUUID(), expiry());

        assertThat(current).isEmpty();
        assertThat(refreshRows(userId)).isZero();
    }

    @Test
    @Tag("AUTH-RESET-04")
    void savesNothing_whenTheUserIsInactive() {
        String inactiveHash = PostgresTestDatabase.bcryptShaped();
        String inactive = PostgresTestDatabase.insertUser(jdbc, "Gone", PostgresTestDatabase.uniqueEmail(), inactiveHash, "SALESPERSON", false);

        assertThat(store.persistRefresh(inactive, inactiveHash, "token-" + UUID.randomUUID(), expiry())).isEmpty();
        assertThat(refreshRows(inactive)).isZero();
    }

    @Test
    @Tag("AUTH-RESET-04")
    void savesNothing_whenTheUserDoesNotExist() {
        String ghost = UUID.randomUUID().toString();

        assertThat(store.persistRefresh(ghost, hash, "token-" + UUID.randomUUID(), expiry())).isEmpty();
        assertThat(refreshRows(ghost)).isZero();
    }

    @Test
    @Tag("AUTH-RESET-04")
    void waitsOnTheSamePerOwnerLockAsResetAndRotation_whateverTheCaseOfTheIdentifier() throws Exception {
        gate = new OwnerLockGate(userId);

        Future<Optional<SystemUser>> persisting = pool.submit(() ->
            store.persistRefresh(userId.toUpperCase(), hash, "token-" + UUID.randomUUID(), expiry()));
        gate.awaitWaiters(1);                                // the database reports it is queued on the owner's lock

        assertThat(persisting.isDone()).as("it cannot save while the lock is held").isFalse();
        assertThat(refreshRows(userId)).isZero();
        gate.release();
        assertThat(persisting.get(30, TimeUnit.SECONDS)).isPresent();
        assertThat(refreshRows(userId)).isEqualTo(1);
    }

    @Test
    @Tag("AUTH-RESET-04")
    void aHashThatChangesWhileItWaitsForTheLockIsRefused() throws Exception {
        gate = new OwnerLockGate(userId);
        String newHash = PostgresTestDatabase.bcryptShaped();

        Future<Optional<SystemUser>> persisting = pool.submit(() ->
            store.persistRefresh(userId, hash, "token-" + UUID.randomUUID(), expiry()));
        gate.awaitWaiters(1);
        try (Connection c = InitializationTestDatabase.adminConnection(); PreparedStatement s = c.prepareStatement(
            "UPDATE auth_schema.system_user SET password_hash = ? WHERE user_id = ?::uuid")) {
            InitializationTestDatabase.requireDisposableDatabase();
            s.setString(1, newHash);
            s.setString(2, userId);
            s.executeUpdate();                                // what a reset commits while the login is parked
        }
        gate.release();

        assertThat(persisting.get(30, TimeUnit.SECONDS)).isEmpty();
        assertThat(refreshRows(userId)).isZero();
    }

    @Test
    @Tag("AUTH-RESET-04")
    void releasesTheLockWhenItEnds_whetherItSavedOrRefused() throws Exception {
        store.persistRefresh(userId, hash, "token-" + UUID.randomUUID(), expiry());
        store.persistRefresh(userId, PostgresTestDatabase.bcryptShaped(), "token-" + UUID.randomUUID(), expiry());

        try (Connection c = InitializationTestDatabase.appConnection();
             PreparedStatement s = c.prepareStatement("SELECT pg_try_advisory_lock(?, hashtext(?))")) {
            s.setInt(1, JdbcRefreshTokenStore.LOCK_NAMESPACE);
            s.setString(2, userId);
            try (ResultSet rs = s.executeQuery()) {
                rs.next();
                assertThat(rs.getBoolean(1)).as("nothing is left holding the owner's lock").isTrue();
            }
        }
    }
}
