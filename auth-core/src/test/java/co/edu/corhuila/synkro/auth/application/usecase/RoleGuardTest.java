package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.domain.model.AuthenticatedCaller;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static co.edu.corhuila.synkro.auth.domain.model.Roles.ADMIN;
import static co.edu.corhuila.synkro.auth.domain.model.Roles.INVENTORY;
import static co.edu.corhuila.synkro.auth.domain.model.Roles.SALESPERSON;
import static co.edu.corhuila.synkro.auth.domain.model.Roles.SERVICE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RoleGuardTest {

    private static AuthenticatedCaller caller(String role, String... permissions) {
        return new AuthenticatedCaller("sub-1", Set.of(role), Set.of(permissions));
    }

    @Test
    void callerWithTheRequiredRole_passes() {
        assertThatCode(() -> RoleGuard.requireAnyRole(caller(ADMIN), "read a user", ADMIN)).doesNotThrowAnyException();
    }

    @Test
    void callerWithAnyOfSeveralAllowedRoles_passes() {
        assertThatCode(() -> RoleGuard.requireAnyRole(caller(SALESPERSON), "create sales", ADMIN, SALESPERSON))
            .doesNotThrowAnyException();
    }

    @Test
    void callerWithoutTheRequiredRole_isForbidden_andTheMessageNamesTheRoleAndTheOperation() {
        assertThatThrownBy(() -> RoleGuard.requireAnyRole(caller(INVENTORY), "create sales", ADMIN, SALESPERSON))
            .isInstanceOf(ForbiddenException.class)
            .hasMessage("Role INVENTORY is not authorized to create sales");
    }

    @Test
    void callerWithoutAnyRole_isForbidden() {
        AuthenticatedCaller noRoles = new AuthenticatedCaller("sub-1", Set.of(), Set.of());

        assertThatThrownBy(() -> RoleGuard.requireAnyRole(noRoles, "read a user", ADMIN))
            .isInstanceOf(ForbiddenException.class)
            .hasMessage("Role (none) is not authorized to read a user");
    }

    @Test
    void aServiceCaller_isRecognised_andRefusedWhereOnlyPeopleAreAllowed() {
        AuthenticatedCaller service = caller(SERVICE, "customers:read");

        assertThat(service.isService()).isTrue();
        assertThat(caller(ADMIN).isService()).isFalse();
        assertThatThrownBy(() -> RoleGuard.requireAnyRole(service, "log out", ADMIN, SALESPERSON, INVENTORY))
            .isInstanceOf(ForbiddenException.class)
            .hasMessage("Role SERVICE is not authorized to log out");
    }

    @Test
    void callerWithTheRequiredPermission_passes_andWithoutItIsForbidden() {
        AuthenticatedCaller reader = caller(INVENTORY, "products:read");

        assertThatCode(() -> RoleGuard.requirePermission(reader, "list products", "products:read")).doesNotThrowAnyException();
        assertThatThrownBy(() -> RoleGuard.requirePermission(reader, "adjust stock", "stock:reserve"))
            .isInstanceOf(ForbiddenException.class)
            .hasMessage("Role INVENTORY is not authorized to adjust stock");
    }

    @Test
    void theCallerExposesItsClaimsAndCopiesThem() {
        AuthenticatedCaller c = caller(ADMIN, "users:manage");

        assertThat(c.hasRole(ADMIN)).isTrue();
        assertThat(c.hasRole(INVENTORY)).isFalse();
        assertThat(c.hasPermission("users:manage")).isTrue();
        assertThat(c.hasPermission("sales:read")).isFalse();
    }

    @Test
    void aCallerWithoutASubject_cannotExist() {
        assertThatThrownBy(() -> new AuthenticatedCaller(" ", Set.of(ADMIN), Set.of()))
            .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new AuthenticatedCaller(null, Set.of(ADMIN), Set.of()))
            .isInstanceOf(IllegalArgumentException.class);
    }
}
