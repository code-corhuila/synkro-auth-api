package co.edu.corhuila.synkro.auth.domain.model;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Mirrors the RBAC tables in 07-api/authentication.md and 00-governance/security-policy.md. */
class RolePermissionsTest {

    @Test
    void admin_hasFullAccess() {
        assertThat(RolePermissions.forRole("ADMIN")).containsExactlyInAnyOrder(
            "customers:create", "customers:read", "customers:update", "customers:delete",
            "products:read", "products:write",
            "sales:create", "sales:read",
            "reports:read", "users:manage");
    }

    @Test
    void salesperson_managesCustomersAndSales_butNotProductWritesOrUsers() {
        assertThat(RolePermissions.forRole("SALESPERSON")).containsExactlyInAnyOrder(
            "customers:create", "customers:read", "customers:update", "customers:delete",
            "products:read",
            "sales:create", "sales:read",
            "reports:read");
    }

    @Test
    void inventory_managesProductsOnly() {
        assertThat(RolePermissions.forRole("INVENTORY")).containsExactlyInAnyOrder("products:read", "products:write");
    }

    @Test
    void noPersonRoleEverCarriesAServiceOnlyPermission() {
        for (String role : new String[] {"ADMIN", "SALESPERSON", "INVENTORY"}) {
            assertThat(RolePermissions.forRole(role))
                .noneMatch(p -> p.startsWith("stock:") || p.startsWith("stock-alerts:") || p.equals("sales:register"));
        }
    }

    @Test
    void unknownRole_isRejected_soNothingIsGrantedByDefault() {
        assertThatThrownBy(() -> RolePermissions.forRole("SERVICE")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> RolePermissions.forRole(null)).isInstanceOf(IllegalArgumentException.class);
    }
}
