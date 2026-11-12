package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.port.out.PasswordResetAttemptLog.Reason;
import co.edu.corhuila.synkro.auth.domain.model.AuthenticatedCaller;
import co.edu.corhuila.synkro.auth.domain.model.Roles;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static co.edu.corhuila.synkro.auth.application.usecase.FakePasswordResetStore.INACTIVE_ID;
import static co.edu.corhuila.synkro.auth.application.usecase.FakePasswordResetStore.MISSING_ID;
import static co.edu.corhuila.synkro.auth.application.usecase.FakePasswordResetStore.SALES_ID;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.ADMIN_CALLER;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.CLOCK;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.CORRELATION_ID;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.PASSWORD_HASHER;
import static co.edu.corhuila.synkro.auth.application.usecase.ResetUserPasswordUseCaseTest.KEY;
import static co.edu.corhuila.synkro.auth.application.usecase.ResetUserPasswordUseCaseTest.NEW_PASSWORD;
import static co.edu.corhuila.synkro.auth.application.usecase.ResetUserPasswordUseCaseTest.command;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** A refused or failed reset is logged with who, which request, which user and why: never with what the body said. */
class ResetUserPasswordRejectionLogTest {

    private record Entry(String correlationId, String callerId, String targetUserId, Reason reason) {}

    private final List<Entry> entries = new ArrayList<>();
    private FakePasswordResetStore store;
    private ResetUserPasswordUseCase reset;

    @BeforeEach
    void setUp() {
        store = new FakePasswordResetStore();
        reset = new ResetUserPasswordUseCase(store, store, PASSWORD_HASHER, () -> "audit-1", CLOCK,
            (correlationId, callerId, targetUserId, reason) -> entries.add(new Entry(correlationId, callerId, targetUserId, reason)));
    }

    private void attempt(AuthenticatedCaller caller, ResetUserPasswordCommand command) {
        try {
            reset.execute(caller, CORRELATION_ID, command);
        } catch (RuntimeException expected) {
            // the log is what these tests look at
        }
    }

    @Test
    void everyKindOfRefusal_isLoggedOnceWithItsReasonAndTheTargetWhenItParsed() {
        attempt(null, command(SALES_ID));
        attempt(new AuthenticatedCaller("svc", Set.of(Roles.SERVICE), Set.of()), command(SALES_ID));
        attempt(ADMIN_CALLER, new ResetUserPasswordCommand(SALES_ID, KEY, "short", "short"));
        attempt(ADMIN_CALLER, command(MISSING_ID));
        attempt(ADMIN_CALLER, command(INACTIVE_ID));

        assertThat(entries).extracting(Entry::reason).containsExactly(
            Reason.UNAUTHENTICATED, Reason.FORBIDDEN, Reason.INVALID_REQUEST, Reason.NOT_FOUND, Reason.BUSINESS_RULE);
        assertThat(entries).extracting(Entry::callerId).containsExactly(
            null, "svc", ADMIN_CALLER.subject(), ADMIN_CALLER.subject(), ADMIN_CALLER.subject());
        assertThat(entries).extracting(Entry::targetUserId).containsExactly(SALES_ID, SALES_ID, SALES_ID, MISSING_ID, INACTIVE_ID);
        assertThat(entries).extracting(Entry::correlationId).containsOnly(CORRELATION_ID);
    }

    @Test
    void aTargetThatIsNotAWellFormedIdentifier_isNeverCopiedIntoTheLog() {
        attempt(ADMIN_CALLER, new ResetUserPasswordCommand("<script>alert(1)</script>", KEY, NEW_PASSWORD, NEW_PASSWORD));
        attempt(ADMIN_CALLER, new ResetUserPasswordCommand(null, KEY, NEW_PASSWORD, NEW_PASSWORD));

        assertThat(entries).extracting(Entry::reason).containsExactly(Reason.INVALID_REQUEST, Reason.INVALID_REQUEST);
        assertThat(entries).extracting(Entry::targetUserId).containsOnlyNulls();
    }

    @Test
    void aReplayThatIsRefusedBecauseTheRequestDiffers_isLoggedAsABusinessRule() {
        reset.execute(ADMIN_CALLER, CORRELATION_ID, command(SALES_ID));

        attempt(ADMIN_CALLER, new ResetUserPasswordCommand(SALES_ID, KEY, "another-passphrase", "another-passphrase"));

        assertThat(entries).extracting(Entry::reason).containsExactly(Reason.BUSINESS_RULE);
    }

    @Test
    void anUnexpectedFailure_isLoggedAsFailed_andStillPropagates() {
        FakePasswordResetStore failing = new FakePasswordResetStore() {
            @Override
            public Outcome resetPasswordWithAudit(String key, String targetUserId, String hash, ResetAttribution attribution) {
                throw new IllegalStateException("audit write failed");
            }
        };
        ResetUserPasswordUseCase broken = new ResetUserPasswordUseCase(failing, failing, PASSWORD_HASHER, () -> "audit-1", CLOCK,
            (correlationId, callerId, targetUserId, reason) -> entries.add(new Entry(correlationId, callerId, targetUserId, reason)));

        assertThatThrownBy(() -> broken.execute(ADMIN_CALLER, CORRELATION_ID, command(SALES_ID)))
            .isInstanceOf(IllegalStateException.class);

        assertThat(entries).extracting(Entry::reason).containsExactly(Reason.FAILED);
    }

    @Test
    void aSuccessfulOrReplayedReset_isNotLoggedAsRejected() {
        reset.execute(ADMIN_CALLER, CORRELATION_ID, command(SALES_ID));
        reset.execute(ADMIN_CALLER, CORRELATION_ID, command(SALES_ID));

        assertThat(entries).isEmpty();
    }

    @Test
    void nothingTheLogReceivesCarriesAPasswordOrAKey() {
        attempt(ADMIN_CALLER, new ResetUserPasswordCommand(SALES_ID, KEY, "short-pw", "different-pw"));
        attempt(ADMIN_CALLER, command(MISSING_ID));

        assertThat(entries.toString()).doesNotContain("short-pw", "different-pw", NEW_PASSWORD, KEY);
    }

    @Test
    void theCommandPrintsNoPassword_soItCannotLeakThroughAMessageOrALogLine() {
        ResetUserPasswordCommand command = new ResetUserPasswordCommand(SALES_ID, KEY, NEW_PASSWORD, NEW_PASSWORD);

        assertThat(command.toString()).doesNotContain(NEW_PASSWORD).contains(SALES_ID);
    }
}
