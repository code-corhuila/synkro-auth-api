package co.edu.corhuila.synkro.auth.domain.model;

import java.util.List;
import java.util.Map;

/**
 * Permissions each person role carries in its access token, per the RBAC tables in
 * 07-api/authentication.md. Service-only permissions (stock:*, stock-alerts:*,
 * sales:register) are deliberately absent: they exist only in service tokens.
 */
public final class RolePermissions {
    private static final Map<String, List<String>> BY_ROLE = Map.of(
        "ADMIN", List.of(
            "customers:create", "customers:read", "customers:update", "customers:delete",
            "products:read", "products:write",
            "sales:create", "sales:read",
            "reports:read", "users:manage"),
        "SALESPERSON", List.of(
            "customers:create", "customers:read", "customers:update", "customers:delete",
            "products:read",
            "sales:create", "sales:read",
            "reports:read"),
        "INVENTORY", List.of("products:read", "products:write"));

    private RolePermissions() {}

    public static List<String> forRole(String role) {
        List<String> permissions = role == null ? null : BY_ROLE.get(role);
        if (permissions == null) {
            throw new IllegalArgumentException(role + " is not a valid person role");
        }
        return permissions;
    }
}
