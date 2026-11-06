package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.port.out.UserRepository;
import co.edu.corhuila.synkro.auth.application.port.out.UserRepository.SearchCriteria;
import co.edu.corhuila.synkro.auth.application.port.out.UserRepository.SearchResult;
import co.edu.corhuila.synkro.auth.application.usecase.ValidationException.Problem;
import co.edu.corhuila.synkro.auth.domain.model.AuthenticatedCaller;
import co.edu.corhuila.synkro.auth.domain.model.Roles;
import co.edu.corhuila.synkro.auth.domain.model.SystemUser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.ADMIN_CALLER;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;

/** AUTH-SEARCH-01/02: filters, role, pagination defaults and the 401/403/400 boundary. */
class SearchUsersUseCaseTest {

    /** Captures the criteria the use case built, and answers a fixed page. */
    private static final class CapturingUsers implements UserRepository {
        SearchCriteria lastCriteria;
        SearchResult nextResult = new SearchResult(List.of(), 0);

        @Override
        public Optional<SystemUser> findByEmail(String email) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Optional<SystemUser> findById(String userId) {
            throw new UnsupportedOperationException();
        }

        @Override
        public SearchResult search(SearchCriteria criteria) {
            lastCriteria = criteria;
            return nextResult;
        }
    }

    private CapturingUsers users;
    private SearchUsersUseCase search;

    @BeforeEach
    void setUp() {
        users = new CapturingUsers();
        search = new SearchUsersUseCase(users);
    }

    private static SearchUsersCommand command(String q, String role, Integer page, Integer limit) {
        return new SearchUsersCommand(q, role, page, limit);
    }

    private Problem problemOf(SearchUsersCommand command) {
        Throwable thrown = catchThrowable(() -> search.execute(ADMIN_CALLER, command));
        assertThat(thrown).isInstanceOf(ValidationException.class);
        return ((ValidationException) thrown).problems().get(0);
    }

    // ── 401/403: the use case enforces it, not just the HTTP layer ────

    @Test
    @Tag("AUTH-SEARCH-02")
    void unauthenticated_aNullCaller_isRefused() {
        assertThatThrownBy(() -> search.execute(null, command(null, null, null, null)))
            .isInstanceOf(UnauthenticatedException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {Roles.SALESPERSON, Roles.INVENTORY, Roles.SERVICE})
    @Tag("AUTH-SEARCH-02")
    void forbidden_anyNonAdminCaller_isRefused_beforeTheRepositoryIsQueried(String role) {
        AuthenticatedCaller caller = new AuthenticatedCaller("caller-1", Set.of(role), Set.of());

        assertThatThrownBy(() -> search.execute(caller, command(null, null, null, null)))
            .isInstanceOf(ForbiddenException.class);

        assertThat(users.lastCriteria).isNull();
    }

    // ── 400: invalid input ─────────────────────────────────────────────

    @Test
    @Tag("AUTH-SEARCH-02")
    void aQLongerThan150Characters_isRejected() {
        assertThat(problemOf(command("q".repeat(151), null, null, null)).field()).isEqualTo("q");
    }

    @Test
    @Tag("AUTH-SEARCH-02")
    void aQOf150Characters_isAccepted() {
        search.execute(ADMIN_CALLER, command("q".repeat(150), null, null, null));

        assertThat(users.lastCriteria.query()).hasSize(150);
    }

    @ParameterizedTest
    @ValueSource(strings = {"SERVICE", "OWNER", "admin"})
    @Tag("AUTH-SEARCH-02")
    void aRoleThatIsNotAHumanRole_isRejected(String role) {
        assertThat(problemOf(command(null, role, null, null)).field()).isEqualTo("role");
    }

    @ParameterizedTest
    @ValueSource(ints = {0, -1})
    @Tag("AUTH-SEARCH-02")
    void aPageBelow1_isRejected(int page) {
        assertThat(problemOf(command(null, null, page, null)).field()).isEqualTo("page");
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 101})
    @Tag("AUTH-SEARCH-02")
    void aLimitOutsideOneTo100_isRejected(int limit) {
        assertThat(problemOf(command(null, null, null, limit)).field()).isEqualTo("limit");
    }

    @Test
    @Tag("AUTH-SEARCH-02")
    void everyInvalidFieldIsReportedAtOnce() {
        Throwable thrown = catchThrowable(() -> search.execute(ADMIN_CALLER, command("q".repeat(151), "OWNER", 0, 101)));

        assertThat(((ValidationException) thrown).problems()).extracting(Problem::field)
            .containsExactlyInAnyOrder("q", "role", "page", "limit");
    }

    // ── defaults and normalization passed to the repository ────────────

    @Test
    @Tag("AUTH-SEARCH-01")
    void noFilters_defaultsToPage1Limit20_andNoQueryOrRole() {
        search.execute(ADMIN_CALLER, command(null, null, null, null));

        assertThat(users.lastCriteria).isEqualTo(new SearchCriteria(null, null, 1, 20));
    }

    @Test
    @Tag("AUTH-SEARCH-01")
    void aBlankQ_isTreatedAsNoFilter() {
        search.execute(ADMIN_CALLER, command("   ", null, null, null));

        assertThat(users.lastCriteria.query()).isNull();
    }

    @Test
    @Tag("AUTH-SEARCH-01")
    void aQAndARole_bothReachTheRepository_trimmed() {
        search.execute(ADMIN_CALLER, command("  ana  ", "SALESPERSON", 3, 10));

        assertThat(users.lastCriteria).isEqualTo(new SearchCriteria("ana", "SALESPERSON", 3, 10));
    }

    @Test
    @Tag("AUTH-SEARCH-01")
    void theRepositoryPageIsReturnedUnchanged_withTheResolvedPageAndLimit() {
        SystemUser u = new SystemUser("u-1", "Ana", "ana@synkro.test", "hash", "ADMIN",
            java.time.Instant.parse("2026-01-01T00:00:00Z"), true);
        users.nextResult = new SearchResult(List.of(u), 1);

        SearchUsersResult result = search.execute(ADMIN_CALLER, command(null, null, 2, 5));

        assertThat(result.items()).containsExactly(u);
        assertThat(result.total()).isEqualTo(1);
        assertThat(result.page()).isEqualTo(2);
        assertThat(result.limit()).isEqualTo(5);
    }
}
