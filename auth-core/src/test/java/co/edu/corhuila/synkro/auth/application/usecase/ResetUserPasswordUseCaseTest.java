package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.port.out.PasswordResetStore.ResetAttribution;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicInteger;

import static co.edu.corhuila.synkro.auth.application.usecase.FakePasswordResetStore.INACTIVE_ID;
import static co.edu.corhuila.synkro.auth.application.usecase.FakePasswordResetStore.INVENTORY_ID;
import static co.edu.corhuila.synkro.auth.application.usecase.FakePasswordResetStore.MISSING_ID;
import static co.edu.corhuila.synkro.auth.application.usecase.FakePasswordResetStore.OTHER_ADMIN_ID;
import static co.edu.corhuila.synkro.auth.application.usecase.FakePasswordResetStore.SALES_ID;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.ADMIN_CALLER;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.CLOCK;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.CORRELATION_ID;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.NOW;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.PASSWORD_HASHER;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** An ADMIN resets the password of an active SALESPERSON or INVENTORY user, and of nobody else. */
class ResetUserPasswordUseCaseTest {

    static final String KEY = "reset-key-0001";
    static final String NEW_PASSWORD = "brand-new-passphrase";

    private FakePasswordResetStore store;
    private AtomicInteger sequence;
    private ResetUserPasswordUseCase reset;

    @BeforeEach
    void setUp() {
        store = new FakePasswordResetStore();
        sequence = new AtomicInteger();
        reset = new ResetUserPasswordUseCase(store, store, PASSWORD_HASHER, () -> "audit-" + sequence.incrementAndGet(),
            CLOCK, Fakes.IGNORED_RESET_ATTEMPTS);
    }

    static ResetUserPasswordCommand command(String targetId) {
        return new ResetUserPasswordCommand(targetId, KEY, NEW_PASSWORD, NEW_PASSWORD);
    }

    @Test
    void anAdminResetsAnActiveSalesperson_theNewPasswordReplacesTheOldOne() {
        ResetUserPasswordResult result = reset.execute(ADMIN_CALLER, CORRELATION_ID, command(SALES_ID));

        assertThat(result.userId()).isEqualTo(SALES_ID);
        assertThat(result.passwordResetAt()).isEqualTo(NOW);
        assertThat(result.replayed()).isFalse();
        var saved = store.findById(SALES_ID).orElseThrow();
        assertThat(PASSWORD_HASHER.matches(NEW_PASSWORD, saved.getPasswordHash())).isTrue();
        assertThat(PASSWORD_HASHER.matches(Fakes.PASSWORD, saved.getPasswordHash())).isFalse();
    }

    @Test
    void anAdminResetsAnActiveInventoryUser() {
        ResetUserPasswordResult result = reset.execute(ADMIN_CALLER, CORRELATION_ID, command(INVENTORY_ID));

        assertThat(result.userId()).isEqualTo(INVENTORY_ID);
        assertThat(PASSWORD_HASHER.matches(NEW_PASSWORD, store.findById(INVENTORY_ID).orElseThrow().getPasswordHash())).isTrue();
    }

    @Test
    void theResultAndTheStoreNeverHoldThePlaintext() {
        ResetUserPasswordResult result = reset.execute(ADMIN_CALLER, CORRELATION_ID, command(SALES_ID));

        assertThat(result.toString()).doesNotContain(NEW_PASSWORD);
        assertThat(store.findById(SALES_ID).orElseThrow().getPasswordHash()).isNotEqualTo(NEW_PASSWORD);
    }

    @Test
    void theTargetsRefreshCredentialsAreRevokedInTheSameUnit_andNobodyElsesAre() {
        reset.execute(ADMIN_CALLER, CORRELATION_ID, command(SALES_ID));

        assertThat(store.revokedOwners).containsExactly(SALES_ID);
    }

    @Test
    void otherUsersAreLeftAsTheyWere() {
        var inventoryBefore = store.findById(INVENTORY_ID).orElseThrow();
        var adminBefore = store.findById(ADMIN_CALLER.subject()).orElseThrow();

        reset.execute(ADMIN_CALLER, CORRELATION_ID, command(SALES_ID));

        assertThat(store.findById(INVENTORY_ID).orElseThrow()).isSameAs(inventoryBefore);
        assertThat(store.findById(ADMIN_CALLER.subject()).orElseThrow()).isSameAs(adminBefore);
    }

    @Test
    void theAuditNamesTheActorFromTheVerifiedCaller_theCorrelationIdAndTheInstant() {
        reset.execute(ADMIN_CALLER, CORRELATION_ID, command(SALES_ID));

        assertThat(store.audits).singleElement().satisfies((ResetAttribution audit) -> {
            assertThat(audit.auditId()).isEqualTo("audit-1");
            assertThat(audit.actorUserId()).isEqualTo(ADMIN_CALLER.subject());
            assertThat(audit.correlationId()).isEqualTo(CORRELATION_ID);
            assertThat(audit.occurredAt()).isEqualTo(NOW);
        });
        assertThat(store.recorded).containsKey(FakePasswordResetStore.slot(ADMIN_CALLER.subject(), KEY));
    }

    @Test
    void anUnknownTarget_isNotFound_andNothingIsWritten() {
        assertThatThrownBy(() -> reset.execute(ADMIN_CALLER, CORRELATION_ID, command(MISSING_ID)))
            .isInstanceOf(NotFoundException.class);

        assertNothingChanged();
    }

    @Test
    void anAdminTarget_isRefusedOnTheId_andNothingIsWritten() {
        assertThatThrownBy(() -> reset.execute(ADMIN_CALLER, CORRELATION_ID, command(OTHER_ADMIN_ID)))
            .isInstanceOfSatisfying(BusinessRuleViolationException.class, e -> assertThat(e.field()).isEqualTo("id"));

        assertNothingChanged();
    }

    @Test
    void theCallerResettingThemselves_isRefusedLikeAnyAdminTarget() {
        assertThatThrownBy(() -> reset.execute(ADMIN_CALLER, CORRELATION_ID, command(ADMIN_CALLER.subject())))
            .isInstanceOfSatisfying(BusinessRuleViolationException.class, e -> assertThat(e.field()).isEqualTo("id"));

        assertNothingChanged();
    }

    @Test
    void anInactiveTarget_isRefusedOnTheId_andNothingIsWritten() {
        assertThatThrownBy(() -> reset.execute(ADMIN_CALLER, CORRELATION_ID, command(INACTIVE_ID)))
            .isInstanceOfSatisfying(BusinessRuleViolationException.class, e -> assertThat(e.field()).isEqualTo("id"));

        assertNothingChanged();
    }

    @Test
    void aTargetThatStopsBeingEligibleBetweenTheCheckAndTheWrite_isRefused_andNothingIsKept() {
        FakePasswordResetStore racing = new FakePasswordResetStore() {
            @Override
            public Outcome resetPasswordWithAudit(String key, String targetUserId, String hash, ResetAttribution attribution) {
                resetCalls++;
                return new Outcome.TargetNotEligible();
            }
        };
        ResetUserPasswordUseCase loser = new ResetUserPasswordUseCase(racing, racing, PASSWORD_HASHER, () -> "audit-x",
            CLOCK, Fakes.IGNORED_RESET_ATTEMPTS);

        assertThatThrownBy(() -> loser.execute(ADMIN_CALLER, CORRELATION_ID, command(SALES_ID)))
            .isInstanceOfSatisfying(BusinessRuleViolationException.class, e -> assertThat(e.field()).isEqualTo("id"));

        assertThat(racing.audits).isEmpty();
        assertThat(racing.revokedOwners).isEmpty();
    }

    @Test
    void aPersistenceFailure_propagates_andIsNotReportedAsASuccess() {
        FakePasswordResetStore failing = new FakePasswordResetStore() {
            @Override
            public Outcome resetPasswordWithAudit(String key, String targetUserId, String hash, ResetAttribution attribution) {
                throw new IllegalStateException("audit write failed");
            }
        };
        ResetUserPasswordUseCase broken = new ResetUserPasswordUseCase(failing, failing, PASSWORD_HASHER, () -> "audit-x",
            CLOCK, Fakes.IGNORED_RESET_ATTEMPTS);

        assertThatThrownBy(() -> broken.execute(ADMIN_CALLER, CORRELATION_ID, command(SALES_ID)))
            .isInstanceOf(IllegalStateException.class);

        assertThat(failing.audits).isEmpty();
    }

    private void assertNothingChanged() {
        assertThat(store.resetCalls).isZero();
        assertThat(store.audits).isEmpty();
        assertThat(store.revokedOwners).isEmpty();
        assertThat(store.recorded).isEmpty();
    }
}
