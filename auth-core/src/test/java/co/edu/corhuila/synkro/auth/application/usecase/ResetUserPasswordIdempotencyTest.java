package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.port.out.PasswordHasher;
import co.edu.corhuila.synkro.auth.application.port.out.PasswordResetStore;
import co.edu.corhuila.synkro.auth.application.port.out.PasswordResetStore.Outcome;
import co.edu.corhuila.synkro.auth.application.port.out.PasswordResetStore.Recorded;
import co.edu.corhuila.synkro.auth.application.port.out.PasswordResetStore.ResetAttribution;
import co.edu.corhuila.synkro.auth.domain.model.AuthenticatedCaller;
import co.edu.corhuila.synkro.auth.domain.model.Roles;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static co.edu.corhuila.synkro.auth.application.usecase.FakePasswordResetStore.INACTIVE_ID;
import static co.edu.corhuila.synkro.auth.application.usecase.FakePasswordResetStore.INVENTORY_ID;
import static co.edu.corhuila.synkro.auth.application.usecase.FakePasswordResetStore.OTHER_ADMIN_ID;
import static co.edu.corhuila.synkro.auth.application.usecase.FakePasswordResetStore.SALES_ID;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.ADMIN_CALLER;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.CLOCK;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.CORRELATION_ID;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.NOW;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.PASSWORD_HASHER;
import static co.edu.corhuila.synkro.auth.application.usecase.ResetUserPasswordUseCaseTest.KEY;
import static co.edu.corhuila.synkro.auth.application.usecase.ResetUserPasswordUseCaseTest.NEW_PASSWORD;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The same Idempotency-Key never resets a password twice, never revokes a session twice, and never reveals what it
 * did to a request that does not match. A key belongs to the administrator that used it.
 */
class ResetUserPasswordIdempotencyTest {

    private FakePasswordResetStore store;
    private AtomicInteger hashCalls;
    private ResetUserPasswordUseCase reset;

    @BeforeEach
    void setUp() {
        store = new FakePasswordResetStore();
        hashCalls = new AtomicInteger();
        PasswordHasher counting = new PasswordHasher() {
            @Override
            public String hash(String plaintext) {
                hashCalls.incrementAndGet();
                return PASSWORD_HASHER.hash(plaintext);
            }

            @Override
            public boolean matches(String plaintext, String hash) {
                return PASSWORD_HASHER.matches(plaintext, hash);
            }
        };
        AtomicInteger sequence = new AtomicInteger();
        reset = new ResetUserPasswordUseCase(store, store, counting, () -> "audit-" + sequence.incrementAndGet(), CLOCK,
            Fakes.IGNORED_RESET_ATTEMPTS);
    }

    private static ResetUserPasswordCommand command(String targetId, String key, String password) {
        return new ResetUserPasswordCommand(targetId, key, password, password);
    }

    @Test
    void theSameKeyAndRequest_answersTheFirstResult_andChangesNothingAgain() {
        ResetUserPasswordResult first = reset.execute(ADMIN_CALLER, CORRELATION_ID, command(SALES_ID, KEY, NEW_PASSWORD));

        ResetUserPasswordResult second = reset.execute(ADMIN_CALLER, "corr-0002", command(SALES_ID, KEY, NEW_PASSWORD));

        assertThat(first.replayed()).isFalse();
        assertThat(second.replayed()).isTrue();
        assertThat(second.userId()).isEqualTo(first.userId());
        assertThat(second.passwordResetAt()).isEqualTo(first.passwordResetAt());
        assertThat(store.audits).hasSize(1);
        assertThat(store.revokedOwners).hasSize(1);
        assertThat(store.resetCalls).isEqualTo(1);
    }

    @Test
    void aReplayDoesNotHashThePasswordAgain() {
        reset.execute(ADMIN_CALLER, CORRELATION_ID, command(SALES_ID, KEY, NEW_PASSWORD));
        reset.execute(ADMIN_CALLER, CORRELATION_ID, command(SALES_ID, KEY, NEW_PASSWORD));

        assertThat(hashCalls).hasValue(1);
    }

    @Test
    void aReplayKeepsTheFirstInstant_evenWhenTheClockHasMovedOn() {
        reset.execute(ADMIN_CALLER, CORRELATION_ID, command(SALES_ID, KEY, NEW_PASSWORD));
        ResetUserPasswordUseCase later = new ResetUserPasswordUseCase(store, store, PASSWORD_HASHER, () -> "audit-9",
            Clock.offset(CLOCK, Duration.ofHours(5)), Fakes.IGNORED_RESET_ATTEMPTS);

        ResetUserPasswordResult replay = later.execute(ADMIN_CALLER, CORRELATION_ID, command(SALES_ID, KEY, NEW_PASSWORD));

        assertThat(replay.passwordResetAt()).isEqualTo(NOW);
    }

    @Test
    void theSameKeyWithAnotherPassword_isRefusedOnTheKey_andChangesNothing() {
        reset.execute(ADMIN_CALLER, CORRELATION_ID, command(SALES_ID, KEY, NEW_PASSWORD));

        assertThatThrownBy(() -> reset.execute(ADMIN_CALLER, CORRELATION_ID, command(SALES_ID, KEY, "another-passphrase")))
            .isInstanceOfSatisfying(BusinessRuleViolationException.class, e -> {
                assertThat(e.field()).isEqualTo("Idempotency-Key");
                assertThat(e.getMessage()).doesNotContain(NEW_PASSWORD, "another-passphrase", SALES_ID);
            });

        assertThat(PASSWORD_HASHER.matches(NEW_PASSWORD, store.findById(SALES_ID).orElseThrow().getPasswordHash())).isTrue();
        assertThat(store.audits).hasSize(1);
    }

    @Test
    void theSameKeyForAnotherTarget_isRefusedOnTheKey_evenWithTheSamePassword() {
        reset.execute(ADMIN_CALLER, CORRELATION_ID, command(SALES_ID, KEY, NEW_PASSWORD));

        assertThatThrownBy(() -> reset.execute(ADMIN_CALLER, CORRELATION_ID, command(INVENTORY_ID, KEY, NEW_PASSWORD)))
            .isInstanceOfSatisfying(BusinessRuleViolationException.class, e -> assertThat(e.field()).isEqualTo("Idempotency-Key"));

        assertThat(store.audits).hasSize(1);
        assertThat(store.revokedOwners).containsExactly(SALES_ID);
    }

    @Test
    void aKeyUsedByAnotherAdmin_isUnknownToThisOne_soThisOneResetsNormally() {
        AuthenticatedCaller other = new AuthenticatedCaller(OTHER_ADMIN_ID, Set.of(Roles.ADMIN), Set.of());
        reset.execute(other, CORRELATION_ID, command(INVENTORY_ID, KEY, "other-admins-secret"));

        ResetUserPasswordResult mine = reset.execute(ADMIN_CALLER, CORRELATION_ID, command(SALES_ID, KEY, NEW_PASSWORD));

        assertThat(mine.replayed()).isFalse();
        assertThat(store.audits).hasSize(2);
        assertThat(store.audits).extracting(ResetAttribution::actorUserId).containsExactly(OTHER_ADMIN_ID, ADMIN_CALLER.subject());
    }

    @Test
    void aReplayDoesNotReEvaluateTheTarget_soItStillAnswersAfterTheTargetWasDeactivated() {
        reset.execute(ADMIN_CALLER, CORRELATION_ID, command(SALES_ID, KEY, NEW_PASSWORD));
        var sales = store.findById(SALES_ID).orElseThrow();
        store.replace(new co.edu.corhuila.synkro.auth.domain.model.SystemUser(sales.getUserId(), sales.getName(),
            sales.getEmail(), sales.getPasswordHash(), sales.getRole(), sales.getRegistrationDate(), false));

        ResetUserPasswordResult replay = reset.execute(ADMIN_CALLER, CORRELATION_ID, command(SALES_ID, KEY, NEW_PASSWORD));

        assertThat(replay.replayed()).isTrue();
        assertThat(store.revokedOwners).hasSize(1);
    }

    @Test
    void whenTheTargetsPasswordChangedAgainAfterTheKeyWasUsed_theOlderRequestIsNoLongerEquivalent() {
        reset.execute(ADMIN_CALLER, CORRELATION_ID, command(SALES_ID, KEY, NEW_PASSWORD));
        reset.execute(ADMIN_CALLER, CORRELATION_ID, command(SALES_ID, "reset-key-0002", "a-later-passphrase"));

        assertThatThrownBy(() -> reset.execute(ADMIN_CALLER, CORRELATION_ID, command(SALES_ID, KEY, NEW_PASSWORD)))
            .isInstanceOfSatisfying(BusinessRuleViolationException.class, e -> assertThat(e.field()).isEqualTo("Idempotency-Key"));

        assertThat(store.audits).hasSize(2);
    }

    @Test
    void anUnauthorizedCallerIsRefusedBeforeTheKeyIsLookedUp_soAReplayIsRefusedLikeAFirstAttempt() {
        reset.execute(ADMIN_CALLER, CORRELATION_ID, command(SALES_ID, KEY, NEW_PASSWORD));
        int lookups = store.lookups;
        AuthenticatedCaller sales = new AuthenticatedCaller(SALES_ID, Set.of(Roles.SALESPERSON), Set.of());

        assertThatThrownBy(() -> reset.execute(sales, CORRELATION_ID, command(SALES_ID, KEY, NEW_PASSWORD)))
            .isInstanceOf(ForbiddenException.class);

        assertThat(store.lookups).isEqualTo(lookups);
    }

    @Test
    void anInvalidRequestIsRefusedBeforeTheKeyIsLookedUp() {
        reset.execute(ADMIN_CALLER, CORRELATION_ID, command(SALES_ID, KEY, NEW_PASSWORD));
        int lookups = store.lookups;

        assertThatThrownBy(() -> reset.execute(ADMIN_CALLER, CORRELATION_ID, command(SALES_ID, KEY, "short")))
            .isInstanceOf(ValidationException.class);

        assertThat(store.lookups).isEqualTo(lookups);
    }

    // ── the race: another request holds the key when this one reaches the atomic unit ─────────────

    private ResetUserPasswordUseCase loserOf(Recorded winner) {
        PasswordResetStore racing = new PasswordResetStore() {
            @Override
            public Optional<Recorded> findByActorAndKey(String actorUserId, String idempotencyKey) {
                return Optional.empty();
            }

            @Override
            public Outcome resetPasswordWithAudit(String key, String targetUserId, String hash, ResetAttribution attribution) {
                return new Outcome.AlreadyRecorded(winner);
            }
        };
        return new ResetUserPasswordUseCase(store, racing, PASSWORD_HASHER, () -> "loser", CLOCK, Fakes.IGNORED_RESET_ATTEMPTS);
    }

    @Test
    void whenAnotherRequestWinsTheRaceWithTheSameRequest_theLoserAnswersTheWinnersResult_withoutChangingAnything() {
        store.replace(new co.edu.corhuila.synkro.auth.domain.model.SystemUser(SALES_ID, "Sales", "sales@synkro.test",
            PASSWORD_HASHER.hash(NEW_PASSWORD), "SALESPERSON", NOW, true));
        ResetUserPasswordUseCase loser = loserOf(new Recorded(SALES_ID, NOW.minusSeconds(2)));

        ResetUserPasswordResult result = loser.execute(ADMIN_CALLER, CORRELATION_ID, command(SALES_ID, KEY, NEW_PASSWORD));

        assertThat(result.replayed()).isTrue();
        assertThat(result.passwordResetAt()).isEqualTo(NOW.minusSeconds(2));
        assertThat(store.audits).isEmpty();
        assertThat(store.revokedOwners).isEmpty();
    }

    @Test
    void whenAnotherRequestWinsTheRaceWithADifferentRequest_theLoserIsRefusedOnTheKey() {
        store.replace(new co.edu.corhuila.synkro.auth.domain.model.SystemUser(SALES_ID, "Sales", "sales@synkro.test",
            PASSWORD_HASHER.hash("the-winners-passphrase"), "SALESPERSON", NOW, true));
        ResetUserPasswordUseCase loser = loserOf(new Recorded(SALES_ID, NOW));

        assertThatThrownBy(() -> loser.execute(ADMIN_CALLER, CORRELATION_ID, command(SALES_ID, KEY, NEW_PASSWORD)))
            .isInstanceOfSatisfying(BusinessRuleViolationException.class, e -> assertThat(e.field()).isEqualTo("Idempotency-Key"));
    }

    @Test
    void aTargetThatIsInactiveOrAnAdmin_isStillRefusedOnTheIdWhenThereIsNoRecord() {
        assertThatThrownBy(() -> reset.execute(ADMIN_CALLER, CORRELATION_ID, command(INACTIVE_ID, KEY, NEW_PASSWORD)))
            .isInstanceOfSatisfying(BusinessRuleViolationException.class, e -> assertThat(e.field()).isEqualTo("id"));
        assertThatThrownBy(() -> reset.execute(ADMIN_CALLER, CORRELATION_ID, command(OTHER_ADMIN_ID, KEY, NEW_PASSWORD)))
            .isInstanceOfSatisfying(BusinessRuleViolationException.class, e -> assertThat(e.field()).isEqualTo("id"));
    }
}
