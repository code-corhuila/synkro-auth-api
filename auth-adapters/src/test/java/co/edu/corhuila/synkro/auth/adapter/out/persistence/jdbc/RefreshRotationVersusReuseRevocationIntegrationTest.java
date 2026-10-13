package co.edu.corhuila.synkro.auth.adapter.out.persistence.jdbc;

import co.edu.corhuila.synkro.auth.adapter.out.crypto.Sha256HashFunction;
import co.edu.corhuila.synkro.auth.application.port.out.HashFunction;
import co.edu.corhuila.synkro.auth.application.port.out.TokenIssuer;
import co.edu.corhuila.synkro.auth.application.usecase.LoginResult;
import co.edu.corhuila.synkro.auth.application.usecase.RefreshUseCase;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Deterministic interleaving, not a stress test: caller A rotates the user's current refresh token and is held
 * after the old token was consumed and before its replacement is saved; caller B presents an already-used token,
 * which revokes every session of the user; then A resumes. The reuse policy says the owner's sessions end, so no
 * refresh token of that user may be usable afterwards.
 */
@EnabledIfEnvironmentVariable(named = PostgresTestDatabase.URL_VARIABLE, matches = ".+")
class RefreshRotationVersusReuseRevocationIntegrationTest {

    private static final Instant IN_AN_HOUR = Instant.now().plus(Duration.ofHours(1));
    private final HashFunction hash = new Sha256HashFunction();

    private JdbcTemplate jdbc;
    private JdbcRefreshTokenStore store;
    private JdbcUserRepository users;
    private String userId;

    @BeforeEach
    void setUp() {
        jdbc = PostgresTestDatabase.jdbcTemplate();
        store = new JdbcRefreshTokenStore(jdbc, PostgresTestDatabase.transactionManager(jdbc));
        users = new JdbcUserRepository(jdbc);
        userId = PostgresTestDatabase.insertUser(jdbc, "ADMIN", true);
    }

    @Test
    void aReuseDetectedWhileAnotherRotationIsInFlight_doesNotLeaveAUsableReplacement() throws Exception {
        String usedEarlier = "used-" + UUID.randomUUID();
        String current = "current-" + UUID.randomUUID();
        store.save(hash.hash(usedEarlier), userId, IN_AN_HOUR);
        store.consume(hash.hash(usedEarlier));
        store.save(hash.hash(current), userId, IN_AN_HOUR);

        CountDownLatch oldTokenConsumed = new CountDownLatch(1);
        CountDownLatch otherCallerFinished = new CountDownLatch(1);
        TokenIssuer heldBetweenConsumeAndSave = new TokenIssuer() {
            @Override
            public String issueAccessToken(String subject, String role) {
                return "access-" + UUID.randomUUID();
            }

            @Override
            public String issueRefreshToken() {
                oldTokenConsumed.countDown();
                await(otherCallerFinished);
                return "replacement-" + UUID.randomUUID();
            }
        };
        RefreshUseCase rotatingCaller = new RefreshUseCase(users, heldBetweenConsumeAndSave, store, hash, Clock.systemUTC(), Duration.ofDays(7));
        RefreshUseCase reusingCaller = new RefreshUseCase(users, new TokenIssuer() {
            @Override
            public String issueAccessToken(String subject, String role) {
                throw new AssertionError("a reused token must not get an access token");
            }

            @Override
            public String issueRefreshToken() {
                throw new AssertionError("a reused token must not get a refresh token");
            }
        }, store, hash, Clock.systemUTC(), Duration.ofDays(7));

        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<LoginResult> rotation = pool.submit(() -> rotatingCaller.execute(current));
            assertThat(oldTokenConsumed.await(10, TimeUnit.SECONDS)).isTrue();

            org.junit.jupiter.api.Assertions.assertThrows(
                co.edu.corhuila.synkro.auth.application.usecase.InvalidCredentialsException.class,
                () -> reusingCaller.execute(usedEarlier));
            otherCallerFinished.countDown();
            rotation.get(10, TimeUnit.SECONDS);
        } finally {
            otherCallerFinished.countDown();
            pool.shutdownNow();
        }

        Integer usable = jdbc.queryForObject(
            "SELECT count(*) FROM auth_schema.refresh_token WHERE user_id = ?::uuid AND active = true AND expiration_date > now()",
            Integer.class, userId);
        assertThat(usable)
            .as("refresh tokens of the user still usable after a reuse revoked all of its sessions")
            .isZero();
    }

    private static void await(CountDownLatch latch) {
        try {
            if (!latch.await(10, TimeUnit.SECONDS)) {
                throw new IllegalStateException("timed out");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }
}
