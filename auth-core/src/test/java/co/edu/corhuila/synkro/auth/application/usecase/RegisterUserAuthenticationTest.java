package co.edu.corhuila.synkro.auth.application.usecase;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.CLOCK;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.CORRELATION_ID;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.PASSWORD_HASHER;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** The use case enforces authentication itself: it does not rely on a gateway or on the HTTP layer. */
class RegisterUserAuthenticationTest {

    private FakeUserRegistrationStore store;
    private RegisterUserUseCase register;

    @BeforeEach
    void setUp() {
        store = new FakeUserRegistrationStore();
        register = new RegisterUserUseCase(store, store, PASSWORD_HASHER, () -> "user-1", CLOCK, Fakes.IGNORED_ATTEMPTS);
    }

    @Test
    @Tag("AUTH-REG-01")
    void case5_aCallWithNoVerifiedCaller_isRefusedByTheUseCase_andWritesNothing() {
        RegisterUserCommand command = new RegisterUserCommand("key-0001-abcd", "Ana", "ana@synkro.test", "a-long-password", "SALESPERSON");

        assertThatThrownBy(() -> register.execute(null, CORRELATION_ID, command))
            .isInstanceOf(UnauthenticatedException.class);

        assertThat(store.registerCalls).isZero();
        assertThat(store.byKey).isEmpty();
    }
}
