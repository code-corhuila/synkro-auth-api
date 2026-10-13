package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.domain.model.AuthenticatedCaller;
import co.edu.corhuila.synkro.auth.domain.model.Roles;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Set;

import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.ADMIN_CALLER;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.CLOCK;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.CORRELATION_ID;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.PASSWORD_HASHER;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Only a human ADMIN registers users, and the use case decides it: the HTTP layer is not the last line. */
class RegisterUserAuthorizationTest {

    private static final String KEY = "key-0001-abcd";

    private FakeUserRegistrationStore store;
    private RegisterUserUseCase register;

    @BeforeEach
    void setUp() {
        store = new FakeUserRegistrationStore();
        register = new RegisterUserUseCase(store, store, PASSWORD_HASHER, () -> "user-1", CLOCK, Fakes.IGNORED_ATTEMPTS);
    }

    private static RegisterUserCommand command() {
        return new RegisterUserCommand(KEY, "Ana Perez", "ana@synkro.test", "a-long-password", "SALESPERSON");
    }

    private static AuthenticatedCaller caller(String role) {
        return new AuthenticatedCaller("00000000-0000-0000-0000-000000000001", Set.of(role), Set.of());
    }

    @ParameterizedTest
    @ValueSource(strings = {Roles.SALESPERSON, Roles.INVENTORY})
    @Tag("AUTH-REG-02")
    void forbidden_aHumanThatIsNotAnAdmin_isForbidden_andWritesNothing(String role) {
        assertThatThrownBy(() -> register.execute(caller(role), CORRELATION_ID, command()))
            .isInstanceOf(ForbiddenException.class);

        assertThat(store.registerCalls).isZero();
        assertThat(store.byKey).isEmpty();
        assertThat(store.byEmail).isEmpty();
    }

    @Test
    @Tag("AUTH-REG-02")
    void forbidden_aServiceIsForbidden_evenWithAKeyThatAlreadyCreatedAUser_andDisclosesNothing() {
        register.execute(ADMIN_CALLER, CORRELATION_ID, command());

        assertThatThrownBy(() -> register.execute(caller(Roles.SERVICE), CORRELATION_ID, command()))
            .isInstanceOfSatisfying(ForbiddenException.class, e ->
                assertThat(e.getMessage()).doesNotContain("ana@synkro.test", "Ana Perez", "user-1"));

        assertThat(store.registerCalls).isEqualTo(1);
    }

    @Test
    @Tag("AUTH-REG-02")
    void forbidden_aCallerThatCarriesBothAdminAndServiceIsStillAService() {
        AuthenticatedCaller both = new AuthenticatedCaller("synkro-workflow", Set.of(Roles.ADMIN, Roles.SERVICE), Set.of());

        assertThatThrownBy(() -> register.execute(both, CORRELATION_ID, command())).isInstanceOf(ForbiddenException.class);

        assertThat(store.registerCalls).isZero();
    }

    @Test
    @Tag("AUTH-REG-02")
    void authorized_anAdmin_proceedsPastAuthorization() {
        RegisterUserResult result = register.execute(ADMIN_CALLER, CORRELATION_ID, command());

        assertThat(result.created()).isTrue();
        assertThat(store.byKey).containsOnlyKeys(KEY);
    }
}
