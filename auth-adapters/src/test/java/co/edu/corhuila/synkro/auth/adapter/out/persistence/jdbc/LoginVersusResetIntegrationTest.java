package co.edu.corhuila.synkro.auth.adapter.out.persistence.jdbc;

import co.edu.corhuila.synkro.auth.adapter.out.crypto.BcryptPasswordHasher;
import co.edu.corhuila.synkro.auth.adapter.out.crypto.Sha256HashFunction;
import co.edu.corhuila.synkro.auth.application.port.out.RefreshTokenStore.Consumption;
import co.edu.corhuila.synkro.auth.application.port.out.TokenIssuer;
import co.edu.corhuila.synkro.auth.application.usecase.InvalidCredentialsException;
import co.edu.corhuila.synkro.auth.application.usecase.LoginResult;
import co.edu.corhuila.synkro.auth.application.usecase.LoginUseCase;
import co.edu.corhuila.synkro.auth.application.usecase.ResetUserPasswordCommand;
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
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Login issuance fencing against a real PostgreSQL (HU-AUTH-19, ADR-021 Decision 3). Login verifies the password
 * outside any lock, then persists its refresh credential under the per-owner lock that password reset and refresh
 * rotation also take. Which one wins is decided by the lock queue, driven through {@link OwnerLockGate}: no test sleeps
 * to make something happen first, and every ordering is the one the database reports.
 *
 * <p>No password or hash is asserted by value in a message: the assertions compare booleans and counts.
 */
@EnabledIfEnvironmentVariable(named = PostgresTestDatabase.URL_VARIABLE, matches = ".+")
class LoginVersusResetIntegrationTest {

    private static final String OLD_PASSWORD = "the-old-passphrase";
    private static final String NEW_PASSWORD = "the-new-passphrase-set-by-the-reset";

    private JdbcTemplate jdbc;
    private BcryptPasswordHasher hasher;
    private JdbcRefreshTokenStore refreshTokens;
    private LoginUseCase login;
    private ResetUserPasswordUseCase reset;
    private AuthenticatedCaller admin;
    private String targetId;
    private String targetEmail;
    private ExecutorService pool;
    private OwnerLockGate gate;

    @BeforeEach
    void setUp() {
        jdbc = PostgresTestDatabase.jdbcTemplate();
        hasher = new BcryptPasswordHasher();
        refreshTokens = new JdbcRefreshTokenStore(jdbc, PostgresTestDatabase.transactionManager(jdbc));
        JdbcUserRepository users = new JdbcUserRepository(jdbc);
        TokenIssuer issuer = new TokenIssuer() {
            @Override
            public String issueAccessToken(String subject, String role) {
                return "access-" + subject + "-" + role;
            }

            @Override
            public String issueRefreshToken() {
                return "refresh-" + UUID.randomUUID();
            }
        };
        login = new LoginUseCase(users, hasher, issuer,
            new JdbcCredentialIssuanceStore(jdbc, PostgresTestDatabase.transactions(jdbc)),
            new Sha256HashFunction(), Clock.systemUTC(), Duration.ofDays(7));
        reset = new ResetUserPasswordUseCase(users,
            new JdbcPasswordResetStore(jdbc, PostgresTestDatabase.transactions(jdbc)), hasher,
            () -> UUID.randomUUID().toString(), Clock.systemUTC(), (correlationId, callerId, target, reason) -> {});
        String adminId = PostgresTestDatabase.insertUser(jdbc, "Admin", PostgresTestDatabase.uniqueEmail(),
            hasher.hash("an-admin-passphrase"), "ADMIN", true);
        admin = new AuthenticatedCaller(adminId, Set.of(Roles.ADMIN), Set.of());
        targetEmail = PostgresTestDatabase.uniqueEmail();
        targetId = PostgresTestDatabase.insertUser(jdbc, "Target", targetEmail, hasher.hash(OLD_PASSWORD), "SALESPERSON", true);
        pool = Executors.newFixedThreadPool(6);
    }

    @AfterEach
    void tearDown() throws Exception {
        if (gate != null) {
            gate.close();
        }
        pool.shutdownNow();
    }

    private Future<Object> resetInBackground(String newPassword) {
        return pool.submit(() -> reset.execute(admin, "corr-" + UUID.randomUUID(),
            new ResetUserPasswordCommand(targetId, "it-key-" + UUID.randomUUID(), newPassword, newPassword)));
    }

    private Future<Object> loginInBackground(String password) {
        return pool.submit(() -> login.execute(targetEmail, password));
    }

    private static Throwable failureOf(Future<?> future) throws InterruptedException {
        try {
            future.get(60, TimeUnit.SECONDS);
            return null;
        } catch (ExecutionException e) {
            return e.getCause();
        } catch (java.util.concurrent.TimeoutException e) {
            throw new AssertionError("the operation did not finish", e);
        }
    }

    private int refreshRows() {
        return jdbc.queryForObject("SELECT count(*) FROM auth_schema.refresh_token WHERE user_id = ?::uuid", Integer.class, targetId);
    }

    private int activeRefreshRows() {
        return jdbc.queryForObject("SELECT count(*) FROM auth_schema.refresh_token WHERE user_id = ?::uuid AND active", Integer.class, targetId);
    }

    private boolean passwordIs(String plaintext) {
        return hasher.matches(plaintext, jdbc.queryForObject(
            "SELECT password_hash FROM auth_schema.system_user WHERE user_id = ?::uuid", String.class, targetId));
    }

    private String existingRefreshToken() {
        String tokenHash = "refresh-existing-" + UUID.randomUUID();
        refreshTokens.save(tokenHash, targetId, Instant.now().plus(7, ChronoUnit.DAYS));
        return tokenHash;
    }

    // ── login and reset ──────────────────────────────────────────────

    @Test
    @Tag("AUTH-RESET-04")
    void loginVerifiesTheOldHash_thenTheResetCommits_thenLoginTriesToPersist_is401_andSavesNoRefreshCredential() throws Exception {
        existingRefreshToken();
        int rowsBefore = refreshRows();
        gate = new OwnerLockGate(targetId);

        Future<Object> resetting = resetInBackground(NEW_PASSWORD);
        gate.awaitWaiters(1);                              // the reset is parked behind the gate, before its writes
        Future<Object> loggingIn = loginInBackground(OLD_PASSWORD);
        gate.awaitWaiters(2);                              // the login verified the old hash and is parked behind the reset
        gate.release();

        assertThat(failureOf(resetting)).as("the reset committed").isNull();
        assertThat(failureOf(loggingIn)).as("the login is the generic 401").isExactlyInstanceOf(InvalidCredentialsException.class);
        assertThat(refreshRows()).as("no refresh credential was saved by the login").isEqualTo(rowsBefore);
        assertThat(activeRefreshRows()).as("and the reset revoked the earlier one").isZero();
        assertThat(passwordIs(NEW_PASSWORD)).isTrue();
    }

    @Test
    @Tag("AUTH-RESET-04")
    void loginCommitsFirst_thenTheResetRuns_andTheRefreshCredentialOfThatLoginIsRevoked() throws Exception {
        int rowsBefore = refreshRows();
        gate = new OwnerLockGate(targetId);

        Future<Object> loggingIn = loginInBackground(OLD_PASSWORD);
        gate.awaitWaiters(1);                              // the login verified the password and is parked behind the gate
        Future<Object> resetting = resetInBackground(NEW_PASSWORD);
        gate.awaitWaiters(2);
        gate.release();

        assertThat(failureOf(loggingIn)).as("the login was first and completed").isNull();
        assertThat(((LoginResult) loggingIn.get()).refreshToken()).isNotBlank();
        assertThat(failureOf(resetting)).isNull();
        assertThat(refreshRows()).as("the login saved exactly one credential").isEqualTo(rowsBefore + 1);
        assertThat(activeRefreshRows()).as("and the reset, which ran after it, revoked it").isZero();
        assertThat(passwordIs(NEW_PASSWORD)).isTrue();
    }

    @Test
    void afterTheReset_loginWithTheNewPasswordWorks_andTheOldPasswordIsRefused() throws Exception {
        assertThat(failureOf(resetInBackground(NEW_PASSWORD))).isNull();

        assertThat(login.execute(targetEmail, NEW_PASSWORD).refreshToken()).isNotBlank();
        assertThat(activeRefreshRows()).as("a session opened after the reset is a live one").isEqualTo(1);
        assertThatThrownBy(() -> login.execute(targetEmail, OLD_PASSWORD)).isInstanceOf(InvalidCredentialsException.class);
    }

    // ── rotation and reset ───────────────────────────────────────────

    @Test
    @Tag("AUTH-RESET-04")
    void aRotationThatWinsTheLockStoresAReplacementThatTheResetThenRevokes() throws Exception {
        String oldToken = existingRefreshToken();
        int rowsBefore = refreshRows();
        gate = new OwnerLockGate(targetId);

        Future<Object> rotating = pool.submit(() ->
            refreshTokens.rotate(oldToken, "replacement-" + UUID.randomUUID(), Instant.now().plus(7, ChronoUnit.DAYS)));
        gate.awaitWaiters(1);
        Future<Object> resetting = resetInBackground(NEW_PASSWORD);
        gate.awaitWaiters(2);
        gate.release();

        assertThat(failureOf(rotating)).isNull();
        assertThat(rotating.get()).isInstanceOf(Consumption.Consumed.class);
        assertThat(failureOf(resetting)).isNull();
        assertThat(refreshRows()).as("the rotation stored its replacement").isEqualTo(rowsBefore + 1);
        assertThat(activeRefreshRows()).as("and the reset revoked the replacement too").isZero();
    }

    @Test
    @Tag("AUTH-RESET-04")
    void aResetThatWinsTheLockLeavesTheRotationNothingToStore() throws Exception {
        String oldToken = existingRefreshToken();
        int rowsBefore = refreshRows();
        gate = new OwnerLockGate(targetId);

        Future<Object> resetting = resetInBackground(NEW_PASSWORD);
        gate.awaitWaiters(1);
        Future<Object> rotating = pool.submit(() ->
            refreshTokens.rotate(oldToken, "replacement-" + UUID.randomUUID(), Instant.now().plus(7, ChronoUnit.DAYS)));
        gate.awaitWaiters(2);
        gate.release();

        assertThat(failureOf(resetting)).isNull();
        assertThat(rotating.get()).as("the token was already revoked by the reset").isInstanceOf(Consumption.AlreadyUsed.class);
        assertThat(refreshRows()).as("nothing was stored").isEqualTo(rowsBefore);
        assertThat(activeRefreshRows()).isZero();
    }

    // ── no deadlock between the three ────────────────────────────────

    @Test
    @Tag("AUTH-RESET-04")
    void loginsResetsAndRotationsOfTheSameOwnerRunTogetherWithoutDeadlock() throws Exception {
        String tokenForRotation = existingRefreshToken();
        List<Callable<Object>> work = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            work.add(() -> login.execute(targetEmail, OLD_PASSWORD));
        }
        for (int i = 0; i < 3; i++) {
            String password = "passphrase-set-by-reset-" + i;
            work.add(() -> reset.execute(admin, "corr-" + UUID.randomUUID(),
                new ResetUserPasswordCommand(targetId, "it-key-" + UUID.randomUUID(), password, password)));
        }
        work.add(() -> refreshTokens.rotate(tokenForRotation, "replacement-" + UUID.randomUUID(), Instant.now().plus(7, ChronoUnit.DAYS)));

        List<Future<Object>> futures = new ArrayList<>();
        for (Callable<Object> task : work) {
            futures.add(pool.submit(task));
        }
        List<Throwable> failures = new ArrayList<>();
        for (Future<Object> future : futures) {
            Throwable failure = failureOf(future);
            if (failure != null) {
                failures.add(failure);
            }
        }

        // A login may be refused (the reset won) and that is the contract; a deadlock or any other failure is not.
        assertThat(failures).allSatisfy(f -> assertThat(f).isExactlyInstanceOf(InvalidCredentialsException.class));
        assertThat(activeRefreshRows()).as("whatever the order, no credential issued before a reset survives it")
            .isZero();
    }
}
