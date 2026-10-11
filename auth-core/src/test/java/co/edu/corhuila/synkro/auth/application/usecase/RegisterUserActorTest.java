package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.port.out.RegistrationAttemptLog.Reason;
import co.edu.corhuila.synkro.auth.domain.model.AuthenticatedCaller;
import co.edu.corhuila.synkro.auth.domain.model.Roles;
import co.edu.corhuila.synkro.auth.domain.model.SystemUser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.ADMIN_CALLER;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.CLOCK;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.CORRELATION_ID;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.PASSWORD_HASHER;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The ADMIN named by the token must exist. A well-formed token for an administrator that is not in the database is
 * refused with a generic 403 before anything else is read, the idempotency key included; a database that cannot
 * answer is an infrastructure failure, never a 403.
 */
class RegisterUserActorTest {

    private static final String KEY = "key-0001-abcd";
    private static final AuthenticatedCaller GHOST_ADMIN =
        new AuthenticatedCaller("00000000-0000-0000-0000-00000000dead", Set.of(Roles.ADMIN), Set.of());

    private static class SpyStore extends FakeUserRegistrationStore {
        final AtomicInteger keyLookups = new AtomicInteger();
        final AtomicInteger emailLookups = new AtomicInteger();

        @Override
        public Optional<SystemUser> findByIdempotencyKey(String idempotencyKey) {
            keyLookups.incrementAndGet();
            return super.findByIdempotencyKey(idempotencyKey);
        }

        @Override
        public Optional<SystemUser> findByEmail(String email) {
            emailLookups.incrementAndGet();
            return super.findByEmail(email);
        }
    }

    private final List<Reason> logged = new ArrayList<>();
    private SpyStore store;
    private RegisterUserUseCase register;

    @BeforeEach
    void setUp() {
        store = new SpyStore();
        AtomicInteger sequence = new AtomicInteger();
        register = new RegisterUserUseCase(store, store, PASSWORD_HASHER, () -> "user-" + sequence.incrementAndGet(), CLOCK,
            (correlationId, callerId, reason) -> logged.add(reason));
    }

    private static RegisterUserCommand command() {
        return new RegisterUserCommand(KEY, "Ana Perez", "ana@synkro.test", "a-long-password", "SALESPERSON");
    }

    @Test
    @Tag("AUTH-REG-02")
    void anAdminThatDoesNotExist_isForbiddenWithAGenericMessage_andNothingIsReadOrWritten() {
        assertThatThrownBy(() -> register.execute(GHOST_ADMIN, CORRELATION_ID, command()))
            .isInstanceOfSatisfying(ForbiddenException.class, e ->
                assertThat(e.getMessage()).doesNotContain(GHOST_ADMIN.subject(), "ana@synkro.test", "Ana Perez", "exist"));

        assertThat(store.keyLookups).hasValue(0);
        assertThat(store.emailLookups).hasValue(0);
        assertThat(store.registerCalls).isZero();
        assertThat(logged).containsExactly(Reason.FORBIDDEN);
    }

    @Test
    @Tag("AUTH-REG-02")
    void aMissingAdminWithAKeyThatAlreadyCreatedAUser_isForbidden_withoutReachingTheKeyLookup() {
        register.execute(ADMIN_CALLER, CORRELATION_ID, command());
        store.keyLookups.set(0);
        store.emailLookups.set(0);

        assertThatThrownBy(() -> register.execute(GHOST_ADMIN, CORRELATION_ID, command()))
            .isInstanceOfSatisfying(ForbiddenException.class, e ->
                assertThat(e.getMessage()).doesNotContain("user-1", "ana@synkro.test", "Ana Perez"));

        assertThat(store.keyLookups).hasValue(0);
        assertThat(store.emailLookups).hasValue(0);
        assertThat(store.registerCalls).isEqualTo(1);
    }

    @Test
    @Tag("AUTH-REG-02")
    void anExistingAdmin_registers_andReplaysWithOneAttribution() {
        RegisterUserResult first = register.execute(ADMIN_CALLER, CORRELATION_ID, command());
        RegisterUserResult replay = register.execute(ADMIN_CALLER, "corr-0002", command());

        assertThat(first.created()).isTrue();
        assertThat(replay.created()).isFalse();
        assertThat(replay.user().getUserId()).isEqualTo(first.user().getUserId());
        assertThat(store.attributions).hasSize(1);
    }

    @Test
    @Tag("AUTH-REG-02")
    void aFailureToLookTheAdminUp_isNotAForbidden_itPropagatesAndIsLoggedAsFailed() {
        FakeUserRegistrationStore broken = new FakeUserRegistrationStore() {
            @Override
            public Optional<SystemUser> findById(String userId) {
                throw new IllegalStateException("database unavailable");
            }
        };
        RegisterUserUseCase failing = new RegisterUserUseCase(broken, broken, PASSWORD_HASHER, () -> "user-1", CLOCK,
            (correlationId, callerId, reason) -> logged.add(reason));

        assertThatThrownBy(() -> failing.execute(ADMIN_CALLER, CORRELATION_ID, command()))
            .isInstanceOf(IllegalStateException.class)
            .isNotInstanceOf(ForbiddenException.class);

        assertThat(broken.registerCalls).isZero();
        assertThat(logged).containsExactly(Reason.FAILED);
    }
}
