package co.edu.corhuila.synkro.auth.domain.model;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * The services that may hold a service token and the permissions each one carries: the table of
 * ADR-006 Decision 2. Permissions are never read from a request or from configuration; a new
 * permission set needs a new ADR, and ServiceAccountTest spells this table out to enforce it.
 */
public enum ServiceAccount {
    WORKFLOW("synkro-workflow", List.of("customers:read", "stock:reserve", "stock:release", "sales:register")),
    WORKER("synkro-worker", List.of("products:read", "stock-alerts:read", "stock-alerts:write"));

    private final String serviceName;
    private final List<String> permissions;

    ServiceAccount(String serviceName, List<String> permissions) {
        this.serviceName = serviceName;
        this.permissions = List.copyOf(permissions);
    }

    public String serviceName() {
        return serviceName;
    }

    public List<String> permissions() {
        return permissions;
    }

    public static Optional<ServiceAccount> fromName(String name) {
        return Arrays.stream(values()).filter(account -> account.serviceName.equals(name)).findFirst();
    }
}
