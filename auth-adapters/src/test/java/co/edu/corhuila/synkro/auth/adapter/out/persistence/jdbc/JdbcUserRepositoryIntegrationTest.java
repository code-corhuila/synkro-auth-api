package co.edu.corhuila.synkro.auth.adapter.out.persistence.jdbc;

import co.edu.corhuila.synkro.auth.domain.model.SystemUser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@EnabledIfEnvironmentVariable(named = PostgresTestDatabase.URL_VARIABLE, matches = ".+")
class JdbcUserRepositoryIntegrationTest {

    private JdbcTemplate jdbc;
    private JdbcUserRepository repository;

    @BeforeEach
    void setUp() {
        jdbc = PostgresTestDatabase.jdbcTemplate();
        repository = new JdbcUserRepository(jdbc);
    }

    @Test
    void findByEmail_returnsTheMappedUser() {
        String email = PostgresTestDatabase.uniqueEmail();
        String id = PostgresTestDatabase.insertUser(jdbc, "Ana Pérez", email, "stored-hash", "SALESPERSON", true);

        SystemUser user = repository.findByEmail(email).orElseThrow();

        assertThat(user.getUserId()).isEqualTo(id);
        assertThat(user.getName()).isEqualTo("Ana Pérez");
        assertThat(user.getEmail()).isEqualTo(email);
        assertThat(user.getPasswordHash()).isEqualTo("stored-hash");
        assertThat(user.getRole()).isEqualTo("SALESPERSON");
        assertThat(user.isActive()).isTrue();
    }

    @Test
    void findById_returnsTheSameUser() {
        String email = PostgresTestDatabase.uniqueEmail();
        String id = PostgresTestDatabase.insertUser(jdbc, "Ana Pérez", email, "stored-hash", "INVENTORY", true);

        SystemUser user = repository.findById(id).orElseThrow();

        assertThat(user.getEmail()).isEqualTo(email);
        assertThat(user.getRole()).isEqualTo("INVENTORY");
    }

    @Test
    void unknownEmailAndUnknownId_areEmpty() {
        assertThat(repository.findByEmail(PostgresTestDatabase.uniqueEmail())).isEmpty();
        assertThat(repository.findById(UUID.randomUUID().toString())).isEmpty();
    }

    @Test
    void anIdThatIsNotAUuid_isEmpty_insteadOfADatabaseError() {
        assertThat(repository.findById("not-a-uuid")).isEmpty();
    }

    @Test
    void aDeactivatedUser_isReturnedAsInactive_soTheUseCaseDecides() {
        String email = PostgresTestDatabase.uniqueEmail();
        String id = PostgresTestDatabase.insertUser(jdbc, "Off", email, "stored-hash", "ADMIN", false);

        assertThat(repository.findByEmail(email).orElseThrow().isActive()).isFalse();
        assertThat(repository.findById(id).orElseThrow().isActive()).isFalse();
    }
}
