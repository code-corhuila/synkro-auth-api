package co.edu.corhuila.synkro.auth.adapter.out.persistence.jdbc;

import co.edu.corhuila.synkro.auth.domain.model.ServiceAccount;
import co.edu.corhuila.synkro.auth.domain.model.ServiceToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@EnabledIfEnvironmentVariable(named = PostgresTestDatabase.URL_VARIABLE, matches = ".+")
class JdbcServiceTokenRepositoryIntegrationTest {

    private JdbcTemplate jdbc;
    private JdbcServiceTokenStore store;
    private JdbcServiceTokenRepository repository;
    private String adminId;

    @BeforeEach
    void setUp() {
        jdbc = PostgresTestDatabase.jdbcTemplate();
        store = new JdbcServiceTokenStore(jdbc, PostgresTestDatabase.transactions(jdbc));
        repository = new JdbcServiceTokenRepository(jdbc);
        adminId = PostgresTestDatabase.insertUser(jdbc, "ADMIN", true);
    }

    private ServiceToken issued(ServiceAccount account) {
        ServiceToken token = ServiceToken.issue(account, UUID.randomUUID().toString(), adminId,
            Instant.now().truncatedTo(ChronoUnit.SECONDS));
        store.issueOnce("it-key-" + UUID.randomUUID(), token);
        return token;
    }

    @Test
    void findById_returnsEveryFieldOfTheMetadataThatWasIssued() {
        ServiceToken workflow = issued(ServiceAccount.WORKFLOW);
        ServiceToken worker = issued(ServiceAccount.WORKER);

        assertThat(repository.findById(workflow.tokenId())).contains(workflow);
        assertThat(repository.findById(worker.tokenId())).contains(worker);
        assertThat(repository.findById(worker.tokenId()).orElseThrow().permissions())
            .containsExactlyInAnyOrder("products:read", "stock-alerts:read", "stock-alerts:write");
    }

    @Test
    void findById_isEmptyForAnUnknownId() {
        assertThat(repository.findById(UUID.randomUUID().toString())).isEmpty();
    }

    @Test
    void findById_isEmptyForTextThatIsNotAnIdentifier_insteadOfFailing() {
        assertThat(repository.findById("not-a-uuid")).isEmpty();
        assertThat(repository.findById("")).isEmpty();
        assertThat(repository.findById(null)).isEmpty();
        assertThat(repository.findById("1' OR '1'='1")).isEmpty();
    }
}
