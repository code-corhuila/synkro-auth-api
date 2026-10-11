package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.port.out.ServiceTokenRepository;
import co.edu.corhuila.synkro.auth.domain.model.AuthenticatedCaller;
import co.edu.corhuila.synkro.auth.domain.model.ServiceAccount;
import co.edu.corhuila.synkro.auth.domain.model.ServiceToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class GetServiceTokenUseCaseTest {

    private static final ServiceToken TOKEN = ServiceToken.issue(ServiceAccount.WORKFLOW, "token-1", "admin-1",
        Instant.parse("2026-03-01T10:15:30Z"));

    private List<String> asked;
    private GetServiceTokenUseCase get;

    private static AuthenticatedCaller caller(String role) {
        return new AuthenticatedCaller("someone", Set.of(role), Set.of());
    }

    @BeforeEach
    void setUp() {
        asked = new ArrayList<>();
        ServiceTokenRepository repository = id -> {
            asked.add(id);
            return "token-1".equals(id) ? Optional.of(TOKEN) : Optional.empty();
        };
        get = new GetServiceTokenUseCase(repository);
    }

    @Test
    void anAdminReadsTheMetadataOfAToken() {
        assertThat(get.execute(caller("ADMIN"), "token-1")).isEqualTo(TOKEN);
    }

    @Test
    void anUnknownIdIsTypedNotFound_withoutSayingWhatWasLookedFor() {
        assertThatThrownBy(() -> get.execute(caller("ADMIN"), "token-2"))
            .isInstanceOfSatisfying(NotFoundException.class, e -> assertThat(e.getMessage()).doesNotContain("token-2"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"SALESPERSON", "INVENTORY", "SERVICE"})
    void anyRoleButAdminIsForbidden_andNothingIsLookedUp(String role) {
        assertThatThrownBy(() -> get.execute(caller(role), "token-1")).isInstanceOf(ForbiddenException.class);
        assertThat(asked).isEmpty();
    }

    @Test
    void theRoleIsCheckedBeforeTheLookup_soAForbiddenCallerLearnsNothingAboutTheId() {
        assertThatThrownBy(() -> get.execute(caller("SALESPERSON"), "token-2")).isInstanceOf(ForbiddenException.class);
    }

    @Test
    void aCallerWithNoRoleIsForbidden() {
        assertThatThrownBy(() -> get.execute(new AuthenticatedCaller("someone", Set.of(), Set.of()), "token-1"))
            .isInstanceOf(ForbiddenException.class);
    }
}
