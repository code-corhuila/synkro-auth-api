package co.edu.corhuila.synkro.auth.adapter.out.persistence.jdbc;

import co.edu.corhuila.synkro.auth.application.port.out.UserRepository.SearchCriteria;
import co.edu.corhuila.synkro.auth.application.port.out.UserRepository.SearchResult;
import co.edu.corhuila.synkro.auth.domain.model.SystemUser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/** AUTH-SEARCH-04: real PostgreSQL, parameter binding and stable pagination (HU-AUTH-18, issue #297). */
@EnabledIfEnvironmentVariable(named = PostgresTestDatabase.URL_VARIABLE, matches = ".+")
class JdbcUserRepositorySearchIntegrationTest {

    private JdbcTemplate jdbc;
    private JdbcUserRepository repository;

    @BeforeEach
    void setUp() {
        jdbc = PostgresTestDatabase.jdbcTemplate();
        repository = new JdbcUserRepository(jdbc);
    }

    private static SearchCriteria criteria(String q, String role, int page, int limit) {
        return new SearchCriteria(q, role, page, limit);
    }

    @Test
    void aSubstringOfTheName_matchesCaseInsensitively() {
        String marker = "Zzq" + UUID.randomUUID().toString().substring(0, 8);
        PostgresTestDatabase.insertUser(jdbc, marker + " Perez", PostgresTestDatabase.uniqueEmail(), "h", "ADMIN", true);

        SearchResult result = repository.search(criteria(marker.toLowerCase(), null, 1, 20));

        assertThat(result.items()).extracting(SystemUser::getName).containsExactly(marker + " Perez");
    }

    @Test
    void aSubstringOfTheEmail_alsoMatches() {
        String marker = "zzq" + UUID.randomUUID().toString().substring(0, 8);
        String email = marker + "@synkro.test";
        PostgresTestDatabase.insertUser(jdbc, "Someone", email, "h", "SALESPERSON", true);

        SearchResult result = repository.search(criteria(marker, null, 1, 20));

        assertThat(result.items()).extracting(SystemUser::getEmail).containsExactly(email);
    }

    @Test
    void aLiteralPercentOrUnderscore_isMatchedAsPlainText_notAsAWildcard() {
        String marker = "zzw" + UUID.randomUUID().toString().substring(0, 8);
        PostgresTestDatabase.insertUser(jdbc, marker + "_literal", PostgresTestDatabase.uniqueEmail(), "h", "ADMIN", true);
        PostgresTestDatabase.insertUser(jdbc, marker + "Xliteral", PostgresTestDatabase.uniqueEmail(), "h", "ADMIN", true);

        SearchResult result = repository.search(criteria(marker + "_literal", null, 1, 20));

        assertThat(result.items()).extracting(SystemUser::getName).containsExactly(marker + "_literal");
    }

    @Test
    void theRoleFilter_narrowsToExactlyThatRole() {
        String marker = "zzr" + UUID.randomUUID();
        PostgresTestDatabase.insertUser(jdbc, marker, PostgresTestDatabase.uniqueEmail(), "h", "ADMIN", true);
        PostgresTestDatabase.insertUser(jdbc, marker, PostgresTestDatabase.uniqueEmail(), "h", "SALESPERSON", true);

        SearchResult result = repository.search(criteria(marker, "ADMIN", 1, 20));

        assertThat(result.items()).extracting(SystemUser::getRole).containsExactly("ADMIN");
    }

    @Test
    void qAndRoleCombine_asAnAndFilter() {
        String marker = "zzc" + UUID.randomUUID();
        PostgresTestDatabase.insertUser(jdbc, marker, PostgresTestDatabase.uniqueEmail(), "h", "ADMIN", true);
        PostgresTestDatabase.insertUser(jdbc, marker, PostgresTestDatabase.uniqueEmail(), "h", "INVENTORY", true);
        PostgresTestDatabase.insertUser(jdbc, "unrelated-" + UUID.randomUUID(), PostgresTestDatabase.uniqueEmail(), "h", "ADMIN", true);

        SearchResult result = repository.search(criteria(marker, "ADMIN", 1, 20));

        assertThat(result.items()).extracting(SystemUser::getName).containsExactly(marker);
    }

    @Test
    void theSafeProjection_neverIncludesThePasswordHash() {
        String marker = "zzh" + UUID.randomUUID();
        PostgresTestDatabase.insertUser(jdbc, marker, PostgresTestDatabase.uniqueEmail(), "a-secret-hash-value", "ADMIN", true);

        SearchResult result = repository.search(criteria(marker, null, 1, 20));

        assertThat(result.items()).extracting(SystemUser::getPasswordHash).containsExactly((String) null);
    }

    @Test
    void paginationIsStable_withIdAsTheTieBreak() {
        String marker = "zzp" + UUID.randomUUID();
        List<String> ids = List.of(
            PostgresTestDatabase.insertUser(jdbc, marker, PostgresTestDatabase.uniqueEmail(), "h", "ADMIN", true),
            PostgresTestDatabase.insertUser(jdbc, marker, PostgresTestDatabase.uniqueEmail(), "h", "ADMIN", true),
            PostgresTestDatabase.insertUser(jdbc, marker, PostgresTestDatabase.uniqueEmail(), "h", "ADMIN", true));

        SearchResult page1 = repository.search(criteria(marker, null, 1, 2));
        SearchResult page2 = repository.search(criteria(marker, null, 2, 2));

        assertThat(page1.total()).isEqualTo(3);
        assertThat(page1.items()).hasSize(2);
        assertThat(page2.items()).hasSize(1);
        List<String> pagedIds = new java.util.ArrayList<>();
        page1.items().forEach(u -> pagedIds.add(u.getUserId()));
        page2.items().forEach(u -> pagedIds.add(u.getUserId()));
        assertThat(pagedIds).containsExactlyInAnyOrderElementsOf(ids);
        assertThat(pagedIds).doesNotHaveDuplicates();
    }

    @Test
    void noFilters_stillReturnsABoundedPage_notEveryRow() {
        SearchResult result = repository.search(criteria(null, null, 1, 1));

        assertThat(result.items()).hasSizeLessThanOrEqualTo(1);
        assertThat(result.total()).isGreaterThanOrEqualTo(result.items().size());
    }
}
