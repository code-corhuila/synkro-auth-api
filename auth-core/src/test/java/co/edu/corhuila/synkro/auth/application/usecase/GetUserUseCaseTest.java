package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.port.out.UserRepository;
import co.edu.corhuila.synkro.auth.domain.model.AuthenticatedCaller;
import co.edu.corhuila.synkro.auth.domain.model.SystemUser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.user;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.users;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class GetUserUseCaseTest {

    private AtomicInteger lookups;
    private GetUserUseCase getUser;

    @BeforeEach
    void setUp() {
        lookups = new AtomicInteger();
        UserRepository stored = users(user("ana@synkro.test", true));
        UserRepository counting = new UserRepository() {
            @Override
            public Optional<SystemUser> findByEmail(String email) {
                return stored.findByEmail(email);
            }

            @Override
            public Optional<SystemUser> findById(String userId) {
                lookups.incrementAndGet();
                return stored.findById(userId);
            }
        };
        getUser = new GetUserUseCase(counting);
    }

    private static AuthenticatedCaller caller(String role) {
        return new AuthenticatedCaller("caller-1", Set.of(role), Set.of());
    }

    @Test
    void anAdmin_getsTheUser() {
        SystemUser found = getUser.execute(caller("ADMIN"), "u-1");

        assertThat(found.getEmail()).isEqualTo("ana@synkro.test");
        assertThat(found.getRole()).isEqualTo("ADMIN");
    }

    @ParameterizedTest
    @ValueSource(strings = {"SALESPERSON", "INVENTORY", "SERVICE"})
    void anyOtherCaller_isForbidden_beforeTheUserIsLookedUp(String role) {
        assertThatThrownBy(() -> getUser.execute(caller(role), "u-1"))
            .isInstanceOf(ForbiddenException.class)
            .hasMessageContaining(role);

        assertThat(lookups).hasValue(0);
    }

    @Test
    void anonymousStyleCallerWithoutRoles_isForbidden() {
        assertThatThrownBy(() -> getUser.execute(new AuthenticatedCaller("caller-1", Set.of(), Set.of()), "u-1"))
            .isInstanceOf(ForbiddenException.class);
    }

    @Test
    void forANonAdmin_anUnknownIdIsStillForbidden_notNotFound() {
        assertThatThrownBy(() -> getUser.execute(caller("SALESPERSON"), "no-such-user"))
            .isInstanceOf(ForbiddenException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"no-such-user", "", "not-a-uuid"})
    void anIdThatDoesNotExist_isATypedNotFound(String id) {
        assertThatThrownBy(() -> getUser.execute(caller("ADMIN"), id)).isInstanceOf(NotFoundException.class);
    }

    @Test
    void aNullId_isATypedNotFound() {
        assertThatThrownBy(() -> getUser.execute(caller("ADMIN"), null)).isInstanceOf(NotFoundException.class);
    }
}
