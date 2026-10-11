package co.edu.corhuila.synkro.auth.domain.model;

import java.util.List;
import java.util.Optional;

public enum ServiceAccount {
    WORKFLOW("synkro-workflow", List.of()),
    WORKER("synkro-worker", List.of());

    private final String serviceName;
    private final List<String> permissions;

    ServiceAccount(String serviceName, List<String> permissions) {
        this.serviceName = serviceName;
        this.permissions = permissions;
    }

    public String serviceName() {
        return serviceName;
    }

    public List<String> permissions() {
        return permissions;
    }

    public static Optional<ServiceAccount> fromName(String name) {
        return Optional.empty();
    }
}
