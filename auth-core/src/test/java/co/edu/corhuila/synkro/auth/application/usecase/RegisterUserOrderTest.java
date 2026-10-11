package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.domain.model.AuthenticatedCaller;
import co.edu.corhuila.synkro.auth.domain.model.Roles;
import co.edu.corhuila.synkro.auth.domain.model.SystemUser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.ADMIN_CALLER;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.CLOCK;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.CORRELATION_ID;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.PASSWORD_HASHER;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** The order of the checks: authorization, then validation, then the idempotency key, then the email. */
class RegisterUserOrderTest {

    private static final String KEY = "key-0001-abcd";

    /** Counts every read, so a test can prove that a refused caller made none. */
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

    private SpyStore store;
    private RegisterUserUseCase register;

    @BeforeEach
    void setUp() {
        store = new SpyStore();
        AtomicInteger sequence = new AtomicInteger();
        register = new RegisterUserUseCase(store, store, PASSWORD_HASHER, () -> "user-" + sequence.incrementAndGet(), CLOCK);
    }

    private static RegisterUserCommand command() {
        return new RegisterUserCommand(KEY, "Ana Perez", "ana@synkro.test", "a-long-password", "SALESPERSON");
    }

    private static AuthenticatedCaller caller(String role) {
        return new AuthenticatedCaller("00000000-0000-0000-0000-000000000001", Set.of(role), Set.of());
    }

    @Test
    @Tag("AUTH-REG-03")
    void case10_aRefusedReplayOfAKnownKey_neverReachesTheIdempotencyLookup() {
        register.execute(ADMIN_CALLER, CORRELATION_ID, command());
        store.keyLookups.set(0);
        store.emailLookups.set(0);

        for (AuthenticatedCaller refused : new AuthenticatedCaller[] {
            null, caller(Roles.SERVICE), caller(Roles.SALESPERSON), caller(Roles.INVENTORY)}) {
            assertThatThrownBy(() -> register.execute(refused, CORRELATION_ID, command()))
                .isInstanceOfAny(UnauthenticatedException.class, ForbiddenException.class);
        }

        assertThat(store.keyLookups).hasValue(0);
        assertThat(store.emailLookups).hasValue(0);
        assertThat(store.registerCalls).isEqualTo(1);
    }

    @Test
    @Tag("AUTH-REG-03")
    void case10b_aRefusedCallerIsRefusedBeforeItsRequestIsValidated() {
        RegisterUserCommand invalid = new RegisterUserCommand("short", "", "nope", "short", "SERVICE");

        assertThatThrownBy(() -> register.execute(caller(Roles.SALESPERSON), CORRELATION_ID, invalid))
            .isInstanceOf(ForbiddenException.class);
    }

    @Test
    @Tag("AUTH-REG-03")
    void case11_anAuthorizedReplay_returnsTheSameUser_andRegistersNothingNew() {
        RegisterUserResult first = register.execute(ADMIN_CALLER, CORRELATION_ID, command());

        RegisterUserResult replay = register.execute(ADMIN_CALLER, "corr-0002", command());

        assertThat(replay.created()).isFalse();
        assertThat(replay.user().getUserId()).isEqualTo(first.user().getUserId());
        assertThat(store.registerCalls).isEqualTo(1);
    }

    @Test
    @Tag("AUTH-REG-03")
    void case12_aDuplicateEmailWithANewKey_isABusinessRuleViolation_andRegistersNothing() {
        register.execute(ADMIN_CALLER, CORRELATION_ID, command());
        RegisterUserCommand sameEmail = new RegisterUserCommand("key-0002-abcd", "Other", "ana@synkro.test", "another-password", "ADMIN");

        assertThatThrownBy(() -> register.execute(ADMIN_CALLER, CORRELATION_ID, sameEmail))
            .isInstanceOfSatisfying(BusinessRuleViolationException.class, e -> assertThat(e.field()).isEqualTo("email"));

        assertThat(store.registerCalls).isEqualTo(1);
        assertThat(store.byKey).containsOnlyKeys(KEY);
    }

    @Test
    @Tag("AUTH-REG-03")
    void case13_serviceAsTheRoleToCreate_isRejectedByTheInputRules_andWritesNothing() {
        RegisterUserCommand serviceUser = new RegisterUserCommand(KEY, "Svc", "svc@synkro.test", "a-long-password", "SERVICE");

        assertThatThrownBy(() -> register.execute(ADMIN_CALLER, CORRELATION_ID, serviceUser))
            .isInstanceOfSatisfying(ValidationException.class, e ->
                assertThat(e.problems()).extracting(ValidationException.Problem::field).contains("role"));

        assertThat(store.registerCalls).isZero();
        assertThat(store.byKey).isEmpty();
    }
}
