package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.port.out.RegistrationAttemptLog.Reason;
import co.edu.corhuila.synkro.auth.domain.model.AuthenticatedCaller;
import co.edu.corhuila.synkro.auth.domain.model.Roles;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.ADMIN_CALLER;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.CLOCK;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.CORRELATION_ID;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.PASSWORD_HASHER;
import static org.assertj.core.api.Assertions.assertThat;

/** A refused or failed registration is logged with who, which request and why: never with what the body said. */
class RegisterUserRejectionLogTest {

    private record Entry(String correlationId, String callerId, Reason reason) {}

    private final List<Entry> entries = new ArrayList<>();
    private FakeUserRegistrationStore store;
    private RegisterUserUseCase register;

    @BeforeEach
    void setUp() {
        store = new FakeUserRegistrationStore();
        register = new RegisterUserUseCase(store, store, PASSWORD_HASHER, () -> "user-1", CLOCK,
            (correlationId, callerId, reason) -> entries.add(new Entry(correlationId, callerId, reason)));
    }

    private static RegisterUserCommand command(String email, String role) {
        return new RegisterUserCommand("key-0001-abcd", "Ana Perez", email, "a-long-password", role);
    }

    private void attempt(AuthenticatedCaller caller, RegisterUserCommand command) {
        try {
            register.execute(caller, CORRELATION_ID, command);
        } catch (RuntimeException expected) {
            // the log is what these tests look at
        }
    }

    @Test
    void everyKindOfRefusal_isLoggedOnceWithItsReason() {
        attempt(null, command("a@synkro.test", "ADMIN"));
        attempt(new AuthenticatedCaller("svc", Set.of(Roles.SERVICE), Set.of()), command("a@synkro.test", "ADMIN"));
        attempt(ADMIN_CALLER, command("nope", "ADMIN"));
        register.execute(ADMIN_CALLER, CORRELATION_ID, command("taken@synkro.test", "ADMIN"));
        attempt(ADMIN_CALLER, new RegisterUserCommand("key-0002-abcd", "Other", "taken@synkro.test", "a-long-password", "ADMIN"));

        assertThat(entries).extracting(Entry::reason).containsExactly(
            Reason.UNAUTHENTICATED, Reason.FORBIDDEN, Reason.INVALID_REQUEST, Reason.BUSINESS_RULE);
        assertThat(entries).extracting(Entry::callerId).containsExactly(null, "svc", ADMIN_CALLER.subject(), ADMIN_CALLER.subject());
        assertThat(entries).extracting(Entry::correlationId).containsOnly(CORRELATION_ID);
    }

    @Test
    void anUnexpectedFailure_isLoggedAsFailed_andStillPropagates() {
        RegisterUserUseCase failing = new RegisterUserUseCase(store, new FakeUserRegistrationStore() {
            @Override
            public Registered registerUserWithAttribution(String key, co.edu.corhuila.synkro.auth.domain.model.SystemUser user,
                                                          CreationAttribution attribution) {
                throw new IllegalStateException("audit write failed");
            }
        }, PASSWORD_HASHER, () -> "user-1", CLOCK,
            (correlationId, callerId, reason) -> entries.add(new Entry(correlationId, callerId, reason)));

        org.assertj.core.api.Assertions.assertThatThrownBy(() -> failing.execute(ADMIN_CALLER, CORRELATION_ID, command("ok@synkro.test", "ADMIN")))
            .isInstanceOf(IllegalStateException.class);

        assertThat(entries).extracting(Entry::reason).containsExactly(Reason.FAILED);
    }

    @Test
    void aSuccessfulRegistration_isNotLoggedAsRejected() {
        register.execute(ADMIN_CALLER, CORRELATION_ID, command("ok@synkro.test", "ADMIN"));

        assertThat(entries).isEmpty();
    }
}
