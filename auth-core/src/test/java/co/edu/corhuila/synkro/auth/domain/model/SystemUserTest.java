package co.edu.corhuila.synkro.auth.domain.model;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SystemUserTest {

    private static SystemUser userWithRole(String role) {
        return new SystemUser("u-1", "Ana", "ana@synkro.test", "hash", role, true);
    }

    @ParameterizedTest
    @ValueSource(strings = {"ADMIN", "SALESPERSON", "INVENTORY"})
    void acceptsEachPersonRole(String role) {
        assertThat(userWithRole(role).getRole()).isEqualTo(role);
    }

    @Test
    void rejectsServiceAsARole_itExistsOnlyInsideServiceTokens() {
        assertThatThrownBy(() -> userWithRole("SERVICE"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("SERVICE");
    }

    @Test
    void rejectsNullRole() {
        assertThatThrownBy(() -> userWithRole(null))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsUnknownRole() {
        assertThatThrownBy(() -> userWithRole("SUPERUSER"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("SUPERUSER");
    }
}
