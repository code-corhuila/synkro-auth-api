package co.edu.corhuila.synkro.auth.adapter.out.persistence.jdbc;

import co.edu.corhuila.synkro.auth.adapter.out.crypto.Rs256ServiceTokenSigner;
import co.edu.corhuila.synkro.auth.application.port.out.ServiceTokenStore.Issued;
import co.edu.corhuila.synkro.auth.application.usecase.BusinessRuleViolationException;
import co.edu.corhuila.synkro.auth.domain.model.ServiceAccount;
import co.edu.corhuila.synkro.auth.domain.model.ServiceToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;

import java.security.KeyPairGenerator;
import java.sql.Array;
import java.time.Instant;
import java.time.OffsetDateTime;
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
class JdbcServiceTokenStoreIntegrationTest {

    private JdbcTemplate jdbc;
    private JdbcServiceTokenStore store;
    private String adminId;

    @BeforeEach
    void setUp() {
        jdbc = PostgresTestDatabase.jdbcTemplate();
        store = new JdbcServiceTokenStore(jdbc, PostgresTestDatabase.transactions(jdbc));
        adminId = PostgresTestDatabase.insertUser(jdbc, "ADMIN", true);
    }

    private static String newKey() {
        return "it-key-" + UUID.randomUUID();
    }

    private ServiceToken newToken(ServiceAccount account) {
        return ServiceToken.issue(account, UUID.randomUUID().toString(), adminId,
            Instant.now().truncatedTo(ChronoUnit.SECONDS));
    }

    private int tokensWithId(String tokenId) {
        return jdbc.queryForObject("SELECT count(*) FROM auth_schema.service_token WHERE token_id = ?::uuid", Integer.class, tokenId);
    }

    private int keysNamed(String key) {
        return jdbc.queryForObject("SELECT count(*) FROM auth_schema.idempotency_key WHERE key = ?", Integer.class, key);
    }

    private int totalTokens() {
        return jdbc.queryForObject("SELECT count(*) FROM auth_schema.service_token", Integer.class);
    }

    // ── what is written ──────────────────────────────────────────────

    @Test
    void issueOnce_persistsEveryColumnOfTheMetadata() throws Exception {
        ServiceToken token = newToken(ServiceAccount.WORKFLOW);

        Issued issued = store.issueOnce(newKey(), token);

        assertThat(issued.created()).isTrue();
        assertThat(issued.token()).isEqualTo(token);
        Map<String, Object> row = jdbc.queryForMap(
            "SELECT token_id::text AS id, service, permissions, issued_by::text AS issued_by, issued_at, expires_at "
                + "FROM auth_schema.service_token WHERE token_id = ?::uuid", token.tokenId());
        assertThat(row.get("id")).isEqualTo(token.tokenId());
        assertThat(row.get("service")).isEqualTo("synkro-workflow");
        assertThat((String[]) ((Array) row.get("permissions")).getArray())
            .containsExactlyInAnyOrder("customers:read", "stock:reserve", "stock:release", "sales:register");
        assertThat(row.get("issued_by")).isEqualTo(adminId);
        assertThat(((java.sql.Timestamp) row.get("issued_at")).toInstant()).isEqualTo(token.issuedAt());
        assertThat(((java.sql.Timestamp) row.get("expires_at")).toInstant()).isEqualTo(token.expiresAt());
    }

    @Test
    void theKeyIsSavedAsTypeServiceTokenPointingAtTheToken_andFindsTheMetadataBack() {
        String key = newKey();
        ServiceToken token = newToken(ServiceAccount.WORKER);
        store.issueOnce(key, token);

        Map<String, Object> row = jdbc.queryForMap(
            "SELECT resource_type, resource_id::text AS resource_id FROM auth_schema.idempotency_key WHERE key = ?", key);
        assertThat(row.get("resource_type")).isEqualTo("SERVICE_TOKEN");
        assertThat(row.get("resource_id")).isEqualTo(token.tokenId());
        assertThat(store.findByIdempotencyKey(key)).contains(token);
        assertThat(store.findByIdempotencyKey(newKey())).isEmpty();
    }

    @Test
    void thereIsNoColumnForTheTokenAndNothingTokenShapedIsStored() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        ServiceToken token = newToken(ServiceAccount.WORKER);
        String signed = new Rs256ServiceTokenSigner(generator.generateKeyPair().getPrivate()).sign(token);
        String key = newKey();
        store.issueOnce(key, token);

        List<String> tokenColumns = jdbc.queryForList(
            "SELECT column_name FROM information_schema.columns WHERE table_schema = 'auth_schema' "
                + "AND table_name = 'service_token' ORDER BY column_name", String.class);
        List<String> keyColumns = jdbc.queryForList(
            "SELECT column_name FROM information_schema.columns WHERE table_schema = 'auth_schema' "
                + "AND table_name = 'idempotency_key' ORDER BY column_name", String.class);
        String dump = jdbc.queryForObject(
            "SELECT (SELECT string_agg(t::text, ' ') FROM auth_schema.service_token t WHERE token_id = ?::uuid) "
                + "|| ' ' || (SELECT string_agg(k::text, ' ') FROM auth_schema.idempotency_key k WHERE key = ?)",
            String.class, token.tokenId(), key);

        assertThat(tokenColumns).containsExactly("expires_at", "issued_at", "issued_by", "permissions", "service", "token_id");
        assertThat(keyColumns).containsExactly("created_at", "key", "resource_id", "resource_type");
        assertThat(dump).doesNotContain(signed).doesNotContain("eyJ");
    }

    // ── idempotency ──────────────────────────────────────────────────

    @Test
    void aDuplicateKey_returnsTheOriginalToken_andCreatesNothing() {
        String key = newKey();
        ServiceToken first = newToken(ServiceAccount.WORKER);
        ServiceToken second = newToken(ServiceAccount.WORKFLOW);
        store.issueOnce(key, first);
        int before = totalTokens();

        Issued again = store.issueOnce(key, second);

        assertThat(again.created()).isFalse();
        assertThat(again.token()).isEqualTo(first);
        assertThat(totalTokens()).isEqualTo(before);
        assertThat(tokensWithId(second.tokenId())).isZero();
        assertThat(keysNamed(key)).isEqualTo(1);
    }

    @Test
    void aKeyAlreadyUsedByAUser_isNotAToken_andIsRefusedNamingTheKey() {
        String key = newKey();
        jdbc.update("INSERT INTO auth_schema.idempotency_key (key, resource_type, resource_id) VALUES (?, 'USER', ?::uuid)",
            key, UUID.randomUUID().toString());
        ServiceToken token = newToken(ServiceAccount.WORKER);

        assertThat(store.findByIdempotencyKey(key)).isEmpty();
        assertThatThrownBy(() -> store.issueOnce(key, token))
            .isInstanceOfSatisfying(BusinessRuleViolationException.class, e -> assertThat(e.field()).isEqualTo("Idempotency-Key"));
        assertThat(tokensWithId(token.tokenId())).isZero();
        assertThat(keysNamed(key)).isEqualTo(1);
    }

    // ── atomicity ────────────────────────────────────────────────────

    @Test
    void ifTheSecondWriteFails_theFirstIsRolledBack_neitherTheKeyNorTheTokenExists() {
        String key = newKey();
        ServiceToken unknownIssuer = ServiceToken.issue(ServiceAccount.WORKER, UUID.randomUUID().toString(),
            UUID.randomUUID().toString(), Instant.now().truncatedTo(ChronoUnit.SECONDS));

        assertThatThrownBy(() -> store.issueOnce(key, unknownIssuer)).isInstanceOf(DataIntegrityViolationException.class);

        assertThat(tokensWithId(unknownIssuer.tokenId())).isZero();
        assertThat(keysNamed(key)).isZero();
    }

    // ── concurrency ──────────────────────────────────────────────────

    private List<Object> runTogether(List<Callable<Issued>> tasks) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(tasks.size());
        CountDownLatch ready = new CountDownLatch(tasks.size());
        CountDownLatch go = new CountDownLatch(1);
        List<Future<Object>> futures = new ArrayList<>();
        for (Callable<Issued> task : tasks) {
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
    void twoSimultaneousIssuesWithTheSameKey_createOneRow_oneCreatedAndOneReplayed() throws Exception {
        for (int round = 0; round < 5; round++) {
            String key = newKey();
            ServiceToken a = newToken(ServiceAccount.WORKER);
            ServiceToken b = newToken(ServiceAccount.WORKER);
            int before = totalTokens();

            List<Object> outcomes = runTogether(List.of(() -> store.issueOnce(key, a), () -> store.issueOnce(key, b)));

            assertThat(outcomes).allSatisfy(o -> assertThat(o).isInstanceOf(Issued.class));
            List<Issued> results = outcomes.stream().map(Issued.class::cast).toList();
            assertThat(results).filteredOn(Issued::created).hasSize(1);
            assertThat(results).filteredOn(r -> !r.created()).hasSize(1);
            assertThat(results.get(0).token()).isEqualTo(results.get(1).token());
            assertThat(totalTokens()).isEqualTo(before + 1);
            assertThat(keysNamed(key)).isEqualTo(1);
        }
    }

    // ── the constraints of the database ──────────────────────────────

    @Test
    void whatTheAdapterWritesRespectsTheServiceAndExpiryChecks_forEveryService() {
        for (ServiceAccount account : ServiceAccount.values()) {
            ServiceToken token = newToken(account);

            assertThat(store.issueOnce(newKey(), token).created()).isTrue();
            assertThat(tokensWithId(token.tokenId())).isEqualTo(1);
        }
    }

    @Test
    void aDirectInsertOfAnotherServiceOrAnExpiryNotAfterTheIssueDate_isRefusedByTheDatabase() {
        String insert = "INSERT INTO auth_schema.service_token (token_id, service, permissions, issued_by, issued_at, expires_at) "
            + "VALUES (?::uuid, ?, ARRAY['x'], ?::uuid, ?, ?)";
        OffsetDateTime now = OffsetDateTime.now();

        assertThatThrownBy(() -> jdbc.update(insert, UUID.randomUUID().toString(), "synkro-sales", adminId, now, now.plusDays(30)))
            .isInstanceOf(DataIntegrityViolationException.class).hasMessageContaining("chk_service_token_service");
        assertThatThrownBy(() -> jdbc.update(insert, UUID.randomUUID().toString(), "synkro-worker", adminId, now, now))
            .isInstanceOf(DataIntegrityViolationException.class).hasMessageContaining("chk_service_token_expiry");
    }

    @Test
    void theServiceUserCannotDeleteATokenOrAKey() {
        ServiceToken token = newToken(ServiceAccount.WORKER);
        String key = newKey();
        store.issueOnce(key, token);

        assertThatThrownBy(() -> jdbc.update("DELETE FROM auth_schema.service_token WHERE token_id = ?::uuid", token.tokenId()))
            .isInstanceOf(DataAccessException.class).hasMessageContaining("permission denied");
        assertThatThrownBy(() -> jdbc.update("DELETE FROM auth_schema.idempotency_key WHERE key = ?", key))
            .isInstanceOf(DataAccessException.class).hasMessageContaining("permission denied");
        assertThat(tokensWithId(token.tokenId())).isEqualTo(1);
    }
}
