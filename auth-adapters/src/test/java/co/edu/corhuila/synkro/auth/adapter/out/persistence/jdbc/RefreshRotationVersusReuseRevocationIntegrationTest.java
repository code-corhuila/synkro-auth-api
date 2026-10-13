package co.edu.corhuila.synkro.auth.adapter.out.persistence.jdbc;

import co.edu.corhuila.synkro.auth.adapter.out.crypto.Sha256HashFunction;
import co.edu.corhuila.synkro.auth.application.port.out.HashFunction;
import co.edu.corhuila.synkro.auth.application.port.out.RefreshTokenStore.Consumption;
import co.edu.corhuila.synkro.auth.application.port.out.TokenIssuer;
import co.edu.corhuila.synkro.auth.application.usecase.InvalidCredentialsException;
import co.edu.corhuila.synkro.auth.application.usecase.RefreshUseCase;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * A rotation (burn the current refresh token, store its replacement) against the revocation of every session of the
 * same owner that a reuse triggers. The reuse policy ends the owner's sessions, so once the revocation has run no
 * refresh token of that owner may be usable, whichever of the two went first.
 */
@EnabledIfEnvironmentVariable(named = PostgresTestDatabase.URL_VARIABLE, matches = ".+")
class RefreshRotationVersusReuseRevocationIntegrationTest {

    private static final Instant IN_AN_HOUR = Instant.now().plus(Duration.ofHours(1));
    private static final Duration TTL = Duration.ofDays(7);

    private final HashFunction hash = new Sha256HashFunction();

    private JdbcTemplate jdbc;
    private JdbcRefreshTokenStore store;
    private String userId;

    @BeforeEach
    void setUp() {
        jdbc = PostgresTestDatabase.jdbcTemplate();
        store = new JdbcRefreshTokenStore(jdbc, PostgresTestDatabase.transactionManager(jdbc));
        userId = PostgresTestDatabase.insertUser(jdbc, "ADMIN", true);
    }

    @Test
    void aRevocationWaitsForARotationInFlight_soTheReplacementIsRevokedWithTheRest() throws Exception {
        TokenPair tokens = seedUsedAndCurrentToken();
        String replacement = hash.hash("replacement-" + UUID.randomUUID());
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            CyclicBarrier lockTaken = new CyclicBarrier(2);
            CyclicBarrier revocationStarted = new CyclicBarrier(2);
            // A rotation in flight: it holds the owner's lock, burns the current token and stores the replacement.
            Future<?> rotationInFlight = pool.submit(() -> PostgresTestDatabase.transactions(jdbc).executeWithoutResult(status -> {
                jdbc.queryForObject("SELECT count(*) FROM (SELECT pg_advisory_xact_lock(?, hashtext(?))) locked",
                    Long.class, JdbcRefreshTokenStore.LOCK_NAMESPACE, userId);
                await(lockTaken);
                jdbc.update("UPDATE auth_schema.refresh_token SET active = false WHERE token = ?", hash.hash(tokens.current()));
                jdbc.update("INSERT INTO auth_schema.refresh_token (user_id, token, expiration_date) VALUES (?::uuid, ?, ?)",
                    userId, replacement, java.sql.Timestamp.from(IN_AN_HOUR));
                await(revocationStarted);
                pause(500);
            }));
            await(lockTaken);
            Future<?> revocation = pool.submit(() -> store.revokeAllOf(userId));
            await(revocationStarted);
            assertThatThrownBy(() -> revocation.get(200, TimeUnit.MILLISECONDS))
                .as("the revocation must wait for the rotation that holds the owner's lock")
                .isInstanceOf(TimeoutException.class);
            rotationInFlight.get(10, TimeUnit.SECONDS);
            revocation.get(10, TimeUnit.SECONDS);
        } finally {
            pool.shutdownNow();
        }

        assertThat(usableTokens(userId)).isZero();
    }

    @Test
    void aRotationAfterTheRevocation_isAReplayAndStoresNothing() {
        TokenPair tokens = seedUsedAndCurrentToken();
        store.revokeAllOf(userId);

        assertThat(store.rotate(hash.hash(tokens.current()), hash.hash("late-" + UUID.randomUUID()), IN_AN_HOUR))
            .isEqualTo(new Consumption.AlreadyUsed(userId));

        assertThat(usableTokens(userId)).isZero();
    }

    @Test
    void aSuccessfulRotation_burnsTheOldTokenAndStoresExactlyOneReplacement() {
        TokenPair tokens = seedUsedAndCurrentToken();
        String replacement = hash.hash("replacement-" + UUID.randomUUID());

        assertThat(store.rotate(hash.hash(tokens.current()), replacement, IN_AN_HOUR)).isEqualTo(new Consumption.Consumed(userId));

        assertThat(usableTokens(userId)).isEqualTo(1);
        assertThat(store.consume(hash.hash(tokens.current()))).isEqualTo(new Consumption.AlreadyUsed(userId));
        assertThat(store.consume(replacement)).isEqualTo(new Consumption.Consumed(userId));
    }

    @Test
    void anUnknownOrExpiredTokenIsNotRotated_andNothingIsStored() {
        String expired = "expired-" + UUID.randomUUID();
        store.save(hash.hash(expired), userId, Instant.now().minus(Duration.ofHours(1)));

        assertThat(store.rotate(hash.hash("never-issued-" + UUID.randomUUID()), hash.hash("a"), IN_AN_HOUR)).isEqualTo(new Consumption.Unknown());
        assertThat(store.rotate(hash.hash(expired), hash.hash("b"), IN_AN_HOUR)).isEqualTo(new Consumption.Unknown());

        assertThat(jdbc.queryForObject("SELECT count(*) FROM auth_schema.refresh_token WHERE user_id = ?::uuid", Integer.class, userId))
            .isEqualTo(1);
    }

    @Test
    void rotationsRacingARevocation_neverLeaveAUsableTokenOnceTheRevocationRan() throws Exception {
        RefreshUseCase useCase = new RefreshUseCase(new JdbcUserRepository(jdbc), new CountingIssuer(), store, hash, Clock.systemUTC(), TTL);
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            for (int round = 0; round < 100; round++) {
                String owner = PostgresTestDatabase.insertUser(jdbc, "ADMIN", true);
                String usedEarlier = "used-" + UUID.randomUUID();
                String current = "current-" + UUID.randomUUID();
                store.save(hash.hash(usedEarlier), owner, IN_AN_HOUR);
                store.consume(hash.hash(usedEarlier));
                store.save(hash.hash(current), owner, IN_AN_HOUR);
                CyclicBarrier start = new CyclicBarrier(2);

                Future<?> rotating = pool.submit(() -> {
                    await(start);
                    return useCase.execute(current);
                });
                Future<?> reusing = pool.submit(() -> {
                    await(start);
                    assertThatThrownBy(() -> useCase.execute(usedEarlier)).isInstanceOf(InvalidCredentialsException.class);
                });
                reusing.get(10, TimeUnit.SECONDS);
                try {
                    rotating.get(10, TimeUnit.SECONDS);
                } catch (ExecutionException rejected) {
                    assertThat(rejected.getCause()).isInstanceOf(InvalidCredentialsException.class);
                }

                assertThat(usableTokens(owner)).as("usable tokens of the owner after the revocation, round " + round).isZero();
            }
        } finally {
            pool.shutdownNow();
        }
    }

    private record TokenPair(String usedEarlier, String current) {}

    /** The owner has one token that was already used (so presenting it is a replay) and one usable token. */
    private TokenPair seedUsedAndCurrentToken() {
        String usedEarlier = "used-" + UUID.randomUUID();
        String current = "current-" + UUID.randomUUID();
        store.save(hash.hash(usedEarlier), userId, IN_AN_HOUR);
        store.consume(hash.hash(usedEarlier));
        store.save(hash.hash(current), userId, IN_AN_HOUR);
        return new TokenPair(usedEarlier, current);
    }

    private int usableTokens(String owner) {
        return jdbc.queryForObject(
            "SELECT count(*) FROM auth_schema.refresh_token WHERE user_id = ?::uuid AND active = true AND expiration_date > now()",
            Integer.class, owner);
    }

    private static void await(CyclicBarrier barrier) {
        try {
            barrier.await(10, TimeUnit.SECONDS);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static void pause(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static final class CountingIssuer implements TokenIssuer {
        @Override
        public String issueAccessToken(String subject, String role) {
            return "access-" + UUID.randomUUID();
        }

        @Override
        public String issueRefreshToken() {
            return "refresh-" + UUID.randomUUID();
        }
    }
}
