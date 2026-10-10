package co.edu.corhuila.synkro.auth.adapter.out.persistence.jdbc;

import co.edu.corhuila.synkro.auth.application.port.out.RefreshTokenStore.Consumption;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import java.util.UUID;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@EnabledIfEnvironmentVariable(named = PostgresTestDatabase.URL_VARIABLE, matches = ".+")
class JdbcRefreshTokenStoreIntegrationTest {

    private static final Instant IN_AN_HOUR = Instant.now().plus(Duration.ofHours(1));

    private JdbcTemplate jdbc;
    private JdbcRefreshTokenStore store;
    private String userId;

    @BeforeEach
    void setUp() {
        jdbc = PostgresTestDatabase.jdbcTemplate();
        store = new JdbcRefreshTokenStore(jdbc);
        userId = PostgresTestDatabase.insertUser(jdbc, "ADMIN", true);
    }

    private static String newHash() {
        return "hash-" + UUID.randomUUID();
    }

    @Test
    void aSavedToken_isConsumedOnce_andReturnsItsOwner() {
        String hash = newHash();
        store.save(hash, userId, IN_AN_HOUR);

        assertThat(store.consume(hash)).isEqualTo(new Consumption.Consumed(userId));
        assertThat(store.consume(hash)).isEqualTo(new Consumption.AlreadyUsed(userId));
    }

    @Test
    void anExpiredToken_isNotConsumed_andStaysActive() {
        String hash = newHash();
        store.save(hash, userId, Instant.now().minus(Duration.ofHours(1)));

        assertThat(store.consume(hash)).isEqualTo(new Consumption.Unknown());
        assertThat(activeOf(hash)).isTrue();
    }

    @Test
    void anUnknownHash_isUnknown() {
        assertThat(store.consume(newHash())).isEqualTo(new Consumption.Unknown());
    }

    @Test
    void twoSimultaneousConsumes_ofTheSameHash_succeedExactlyOnce() throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            for (int round = 0; round < 50; round++) {
                String hash = newHash();
                store.save(hash, userId, IN_AN_HOUR);
                CyclicBarrier start = new CyclicBarrier(2);

                List<Future<Consumption>> results = new ArrayList<>();
                for (int caller = 0; caller < 2; caller++) {
                    results.add(pool.submit(() -> {
                        start.await();
                        return store.consume(hash);
                    }));
                }

                long winners = 0;
                for (Future<Consumption> result : results) {
                    winners += result.get() instanceof Consumption.Consumed ? 1 : 0;
                }
                assertThat(winners).as("winners in round %d", round).isEqualTo(1);
            }
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void theStoredToken_isTheHashGiven_andConsumingKeepsTheRowInactive() {
        String hash = newHash();
        store.save(hash, userId, IN_AN_HOUR);

        assertThat(rowsWithToken(hash)).isEqualTo(1);
        assertThat(activeOf(hash)).isTrue();

        store.consume(hash);

        assertThat(rowsWithToken(hash)).isEqualTo(1);
        assertThat(activeOf(hash)).isFalse();
    }

    @Test
    void theServiceUser_cannotDeleteRefreshTokens() {
        String hash = newHash();
        store.save(hash, userId, IN_AN_HOUR);

        assertThatThrownBy(() -> jdbc.update("DELETE FROM auth_schema.refresh_token WHERE token = ?", hash))
            .isInstanceOf(DataAccessException.class)
            .rootCause().hasMessageContaining("permission denied");
        assertThat(rowsWithToken(hash)).isEqualTo(1);
    }

    @Test
    void consume_ofAUsableToken_isConsumedWithItsOwner_andBurnsTheRow() {
        String hash = newHash();
        store.save(hash, userId, IN_AN_HOUR);

        assertThat(store.consume(hash)).isEqualTo(new Consumption.Consumed(userId));
        assertThat(activeOf(hash)).isFalse();
    }

    @Test
    void consume_ofATokenAlreadyConsumed_isAlreadyUsedWithItsOwner() {
        String hash = newHash();
        store.save(hash, userId, IN_AN_HOUR);
        store.consume(hash);

        assertThat(store.consume(hash)).isEqualTo(new Consumption.AlreadyUsed(userId));
    }

    @Test
    void consume_ofAnInactiveTokenThatHasExpired_isUnknown() {
        String hash = newHash();
        insertRow(hash, Instant.now().minus(Duration.ofHours(1)), false);

        assertThat(store.consume(hash)).isEqualTo(new Consumption.Unknown());
    }

    @Test
    void consume_ofAnActiveTokenThatHasExpired_isUnknown_andStaysActive() {
        String hash = newHash();
        store.save(hash, userId, Instant.now().minus(Duration.ofHours(1)));

        assertThat(store.consume(hash)).isEqualTo(new Consumption.Unknown());
        assertThat(activeOf(hash)).isTrue();
    }

    @Test
    void consume_ofAnUnknownHash_isUnknown() {
        assertThat(store.consume(newHash())).isEqualTo(new Consumption.Unknown());
    }

    private void insertRow(String hash, Instant expiresAt, boolean active) {
        jdbc.update("INSERT INTO auth_schema.refresh_token (user_id, token, expiration_date, active) VALUES (?, ?, ?, ?)",
            UUID.fromString(userId), hash, java.sql.Timestamp.from(expiresAt), active);
    }

    private int rowsWithToken(String hash) {
        return jdbc.queryForObject("SELECT count(*) FROM auth_schema.refresh_token WHERE token = ?", Integer.class, hash);
    }

    private boolean activeOf(String hash) {
        return jdbc.queryForObject("SELECT active FROM auth_schema.refresh_token WHERE token = ?", Boolean.class, hash);
    }
}
