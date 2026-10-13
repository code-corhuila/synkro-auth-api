package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.port.out.InitialAdminStore.InitializationAudit;
import co.edu.corhuila.synkro.auth.application.usecase.InitializationFailedException.Kind;
import co.edu.corhuila.synkro.auth.application.usecase.ValidationException.Problem;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** HU-AUTH-14: attribution, repetition and failure handling of the initialization use case. */
class InitializeAdminOutcomesTest {

    private static final String OPERATOR = "deploy-pipeline@release-7";
    private static final String CORRELATION = "init-corr-0001";
    private static final String PASSWORD = "initial-admin-secret";

    private final FakeInitialAdminStore store = new FakeInitialAdminStore();
    private final AtomicInteger ids = new AtomicInteger();
    // A clock that carries nanoseconds, which PostgreSQL would not keep.
    private final Clock clock = Clock.fixed(Instant.parse("2026-03-04T05:06:07.123456789Z"), ZoneOffset.UTC);
    private final InitializeAdminUseCase useCase = new InitializeAdminUseCase(store, Fakes.PASSWORD_HASHER,
        () -> "id-" + ids.incrementAndGet(), clock);

    private static InitialAdminCommand valid() {
        return new InitialAdminCommand("Ada Admin", "  Ada.Admin@Synkro.TEST ", PASSWORD, "  " + OPERATOR + " ", CORRELATION);
    }

    @Test
    void writesMicrosecondTimestampsAndAnAuditIdDistinctFromTheUserId() {
        useCase.execute(valid());

        assertThat(store.savedAdmin.getRegistrationDate()).isEqualTo(Instant.parse("2026-03-04T05:06:07.123456Z"));
        InitializationAudit audit = store.savedAudit;
        assertThat(audit.occurredAt()).isEqualTo(Instant.parse("2026-03-04T05:06:07.123456Z"));
        assertThat(audit.auditId()).isNotBlank().isNotEqualTo(store.savedAdmin.getUserId());
        assertThat(audit.operatorIdentity()).as("surrounding whitespace is not part of the identity").isEqualTo(OPERATOR);
        assertThat(audit.correlationId()).isEqualTo(CORRELATION);
    }

    @Test
    void repeatingTheExecutionAfterACreationIsANoOpThatNamesNoUser() {
        InitialAdminResult first = useCase.execute(valid());

        InitialAdminResult again = useCase.execute(valid());

        assertThat(first.created()).isTrue();
        assertThat(again).isEqualTo(new InitialAdminResult(false, null));
        assertThat(store.calls).isEqualTo(2);
    }

    @Test
    void namesEveryOffendingFieldAndNeverRepeatsTheSecret() {
        assertThatThrownBy(() -> useCase.execute(new InitialAdminCommand("", "nope", "short", "", "")))
            .isInstanceOfSatisfying(ValidationException.class, e -> {
                assertThat(e.problems()).extracting(Problem::field)
                    .containsExactlyInAnyOrder("operator", "correlationId", "name", "email", "password");
                assertThat(e.problems().toString()).doesNotContain("short").doesNotContain("nope");
            });
        assertThat(store.calls).isZero();
    }

    @Test
    void acceptsAnOperatorIdentityOfExactlyTwoHundredCharactersAndCountsCharactersNotUtf16Units() {
        useCase.execute(new InitialAdminCommand("Ada", "a@b.co", PASSWORD, "o".repeat(200), CORRELATION));
        assertThat(store.savedAudit.operatorIdentity()).hasSize(200);

        // 200 supplementary characters are 400 UTF-16 units but 200 characters for PostgreSQL's char_length.
        FakeInitialAdminStore other = new FakeInitialAdminStore();
        new InitializeAdminUseCase(other, Fakes.PASSWORD_HASHER, () -> "id", clock)
            .execute(new InitialAdminCommand("Ada", "a@b.co", PASSWORD, "😀".repeat(200), CORRELATION));
        assertThat(other.savedAdmin).isNotNull();
    }

    @Test
    void letsAStoreFailureReachTheCallerWithoutAResult() {
        store.failure = new InitializationFailedException(Kind.LOCK_TIMEOUT, "55P03");

        assertThatThrownBy(() -> useCase.execute(valid()))
            .isInstanceOfSatisfying(InitializationFailedException.class, e -> {
                assertThat(e.kind()).isEqualTo(Kind.LOCK_TIMEOUT);
                assertThat(e.sqlState()).isEqualTo("55P03");
            });
        assertThat(store.savedAdmin).isNull();
    }

    @Test
    void anAuthorizedRetryAfterAFailureCreatesTheAdministrator() {
        store.failure = new InitializationFailedException(Kind.DATABASE, "08006");
        assertThatThrownBy(() -> useCase.execute(valid())).isInstanceOf(InitializationFailedException.class);
        store.failure = null;

        assertThat(useCase.execute(valid()).created()).isTrue();
    }

    @Test
    void failureMessagesCarryNeitherPasswordNorHashNorCause() {
        InitializationFailedException failure = new InitializationFailedException(Kind.OUTCOME_UNCERTAIN, "08006");

        assertThat(failure.getMessage()).doesNotContain(PASSWORD).doesNotContain("hashed").contains("08006");
        assertThat(failure.getCause()).isNull();
        assertThat(new InitializationFailedException(Kind.DATABASE, null).sqlState()).isEqualTo("unknown");
    }
}
