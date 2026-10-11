package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.port.out.ServiceTokenSigner;
import co.edu.corhuila.synkro.auth.application.port.out.ServiceTokenStore;
import co.edu.corhuila.synkro.auth.application.usecase.ValidationException.Problem;
import co.edu.corhuila.synkro.auth.domain.model.AuthenticatedCaller;
import co.edu.corhuila.synkro.auth.domain.model.ServiceToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class IssueServiceTokenUseCaseTest {

    private static final String KEY = "key-0001-abcd";
    private static final String ADMIN_ID = "11111111-1111-4111-8111-111111111111";
    // Not on a second boundary: the use case must truncate it, because a JWT cannot carry fractions.
    private static final Instant NOW = Instant.parse("2026-03-01T10:15:30.987654Z");

    private FakeServiceTokenStore store;
    private List<ServiceToken> signed;
    private AtomicInteger sequence;
    private IssueServiceTokenUseCase issue;

    private static AuthenticatedCaller caller(String subject, String... roles) {
        return new AuthenticatedCaller(subject, Set.of(roles), Set.of());
    }

    private static AuthenticatedCaller admin() {
        return caller(ADMIN_ID, "ADMIN");
    }

    private static IssueServiceTokenCommand command(String key, String service) {
        return new IssueServiceTokenCommand(key, service);
    }

    private IssueServiceTokenUseCase useCase(ServiceTokenStore tokenStore) {
        ServiceTokenSigner signer = token -> {
            signed.add(token);
            return "signed.jwt." + token.tokenId();
        };
        return new IssueServiceTokenUseCase(tokenStore, signer, () -> "token-" + sequence.incrementAndGet(),
            Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @BeforeEach
    void setUp() {
        store = new FakeServiceTokenStore();
        signed = new ArrayList<>();
        sequence = new AtomicInteger();
        issue = useCase(store);
    }

    // ── issuing ──────────────────────────────────────────────────────

    @Test
    void anAdminIssuesATokenForTheWorker_withExactlyTheThreeWorkerPermissions() {
        IssueServiceTokenResult result = issue.execute(admin(), command(KEY, "synkro-worker"));

        assertThat(result.created()).isTrue();
        ServiceToken token = result.token();
        assertThat(token.service()).isEqualTo("synkro-worker");
        assertThat(token.permissions()).containsExactlyInAnyOrder("products:read", "stock-alerts:read", "stock-alerts:write");
        assertThat(token.tokenId()).isEqualTo("token-1");
    }

    @Test
    void theTokenIsIssuedByTheCallerAndNotByAnythingInTheRequest() {
        IssueServiceTokenResult result = issue.execute(caller("another-admin", "ADMIN"), command(KEY, "synkro-workflow"));

        assertThat(result.token().issuedBy()).isEqualTo("another-admin");
    }

    @Test
    void theDatesComeFromTheInjectedClock_truncatedToTheSecond_andExpiryIsThirtyDaysLater() {
        ServiceToken token = issue.execute(admin(), command(KEY, "synkro-workflow")).token();

        assertThat(token.issuedAt()).isEqualTo(Instant.parse("2026-03-01T10:15:30Z"));
        assertThat(token.expiresAt()).isEqualTo(token.issuedAt().plus(Duration.ofDays(30)));
    }

    @Test
    void theWorkflowGetsItsFourPermissions() {
        ServiceToken token = issue.execute(admin(), command(KEY, "synkro-workflow")).token();

        assertThat(token.permissions())
            .containsExactlyInAnyOrder("customers:read", "stock:reserve", "stock:release", "sales:register");
    }

    @Test
    void theSignedTokenIsReturnedOnceAndIsTheOneSignedFromTheSavedMetadata() {
        IssueServiceTokenResult result = issue.execute(admin(), command(KEY, "synkro-worker"));

        assertThat(signed).containsExactly(result.token());
        assertThat(result.signedToken()).isEqualTo("signed.jwt.token-1");
        assertThat(store.byKey).containsEntry(KEY, result.token());
    }

    @Test
    void theResultNeverPrintsTheSignedToken() {
        IssueServiceTokenResult result = issue.execute(admin(), command(KEY, "synkro-worker"));

        assertThat(result.toString()).doesNotContain(result.signedToken()).contains("token-1");
    }

    // ── idempotency ──────────────────────────────────────────────────

    @Test
    void theSameKeyAndBody_returnsTheStoredMetadata_withNoToken_andSavesNothingNew() {
        IssueServiceTokenResult first = issue.execute(admin(), command(KEY, "synkro-worker"));

        IssueServiceTokenResult second = issue.execute(admin(), command(KEY, "synkro-worker"));

        assertThat(second.created()).isFalse();
        assertThat(second.signedToken()).isNull();
        assertThat(second.token()).isEqualTo(first.token());
        assertThat(store.byKey).hasSize(1);
        assertThat(store.issueCalls).isEqualTo(1);
        assertThat(signed).hasSize(1);
        assertThat(sequence).hasValue(1);
    }

    @Test
    void theSameKeyWithAnotherService_isRefusedNamingTheKey_andShowsNothingOfTheFirstToken() {
        IssueServiceTokenResult first = issue.execute(admin(), command(KEY, "synkro-worker"));

        assertThatThrownBy(() -> issue.execute(admin(), command(KEY, "synkro-workflow")))
            .isInstanceOfSatisfying(BusinessRuleViolationException.class, e -> {
                assertThat(e.field()).isEqualTo("Idempotency-Key");
                assertThat(e.getMessage()).doesNotContain("token-1", ADMIN_ID, first.signedToken());
            });
        assertThat(store.byKey).hasSize(1);
        assertThat(store.issueCalls).isEqualTo(1);
    }

    @Test
    void whenAnotherRequestWinsTheRace_theLoserGetsTheWinnersMetadata_withoutAToken() {
        ServiceToken winner = ServiceToken.issue(co.edu.corhuila.synkro.auth.domain.model.ServiceAccount.WORKER,
            "winner-id", ADMIN_ID, Instant.parse("2026-03-01T10:15:29Z"));
        ServiceTokenStore racing = new ServiceTokenStore() {
            @Override
            public Optional<ServiceToken> findByIdempotencyKey(String idempotencyKey) {
                return Optional.empty();
            }

            @Override
            public Issued issueOnce(String idempotencyKey, ServiceToken token) {
                return new Issued(winner, false);
            }
        };

        IssueServiceTokenResult result = useCase(racing).execute(admin(), command(KEY, "synkro-worker"));

        assertThat(result.created()).isFalse();
        assertThat(result.signedToken()).isNull();
        assertThat(result.token().tokenId()).isEqualTo("winner-id");
    }

    @Test
    void whenAnotherRequestWinsTheRaceWithAnotherService_theLoserIsRefused() {
        ServiceToken winner = ServiceToken.issue(co.edu.corhuila.synkro.auth.domain.model.ServiceAccount.WORKER,
            "winner-id", ADMIN_ID, Instant.parse("2026-03-01T10:15:29Z"));
        ServiceTokenStore racing = new ServiceTokenStore() {
            @Override
            public Optional<ServiceToken> findByIdempotencyKey(String idempotencyKey) {
                return Optional.empty();
            }

            @Override
            public Issued issueOnce(String idempotencyKey, ServiceToken token) {
                return new Issued(winner, false);
            }
        };

        assertThatThrownBy(() -> useCase(racing).execute(admin(), command(KEY, "synkro-workflow")))
            .isInstanceOfSatisfying(BusinessRuleViolationException.class, e -> assertThat(e.field()).isEqualTo("Idempotency-Key"));
    }

    @Test
    void ifTheStoreFails_nothingIsReturned_andNoErrorCarriesTheSignedToken() {
        store.failure = new IllegalStateException("commit failed");

        assertThatThrownBy(() -> issue.execute(admin(), command(KEY, "synkro-worker")))
            .isSameAs(store.failure)
            .satisfies(e -> assertThat(String.valueOf(e.getMessage())).doesNotContain("signed.jwt"));
        assertThat(store.byKey).isEmpty();
    }

    // ── validation ───────────────────────────────────────────────────

    @Test
    void aMissingKey_isAValidationErrorNamingTheKey() {
        assertProblems(command(null, "synkro-worker"), "Idempotency-Key");
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1, 7, 129, 500})
    void aKeyOutsideEightToOneHundredTwentyEightCharacters_isAValidationErrorNamingTheKey(int length) {
        assertProblems(command("k".repeat(length), "synkro-worker"), "Idempotency-Key");
    }

    @ParameterizedTest
    @ValueSource(ints = {8, 128})
    void theLimitsOfTheKeyAreAccepted(int length) {
        assertThat(issue.execute(admin(), command("k".repeat(length), "synkro-worker")).created()).isTrue();
    }

    @Test
    void aMissingService_isAValidationErrorNamingTheService() {
        assertProblems(command(KEY, null), "service");
        assertProblems(command(KEY, ""), "service");
        assertProblems(command(KEY, "  "), "service");
    }

    @ParameterizedTest
    @ValueSource(strings = {"synkro-sales", "SYNKRO-WORKER", "worker", "synkro-worker ", "ADMIN"})
    void anUnknownService_isAValidationErrorNamingTheService(String service) {
        assertProblems(command(KEY, service), "service");
    }

    @Test
    void everyProblemIsReportedAtOnce() {
        assertProblems(command("short", "nope"), "Idempotency-Key", "service");
    }

    private void assertProblems(IssueServiceTokenCommand command, String... fields) {
        assertThatThrownBy(() -> issue.execute(admin(), command))
            .isInstanceOfSatisfying(ValidationException.class, e ->
                assertThat(e.problems()).extracting(Problem::field).containsExactly(fields));
        assertThat(store.byKey).isEmpty();
        assertThat(signed).isEmpty();
    }

    // ── roles ────────────────────────────────────────────────────────

    @ParameterizedTest
    @ValueSource(strings = {"SALESPERSON", "INVENTORY", "SERVICE"})
    void anyRoleButAdmin_isForbidden_andNothingIsSignedOrSaved(String role) {
        assertThatThrownBy(() -> issue.execute(caller("someone", role), command(KEY, "synkro-worker")))
            .isInstanceOf(ForbiddenException.class);
        assertThat(store.byKey).isEmpty();
        assertThat(store.issueCalls).isZero();
        assertThat(signed).isEmpty();
    }

    @Test
    void theRoleIsCheckedBeforeTheInput() {
        assertThatThrownBy(() -> issue.execute(caller("someone", "SALESPERSON"), command(null, "nope")))
            .isInstanceOf(ForbiddenException.class);
    }

    @Test
    void aCallerWithNoRoleIsForbidden() {
        assertThatThrownBy(() -> issue.execute(new AuthenticatedCaller("someone", Set.of(), Set.of()), command(KEY, "synkro-worker")))
            .isInstanceOf(ForbiddenException.class);
    }
}
