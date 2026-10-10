package co.edu.corhuila.synkro.auth.domain.model;

import java.util.Set;

/** Who is calling, as proven by a verified access token: identity, roles and permissions come only from its claims. */
public record AuthenticatedCaller(String subject, Set<String> roles, Set<String> permissions) {

    public AuthenticatedCaller {
        if (subject == null || subject.isBlank()) {
            throw new IllegalArgumentException("subject is required");
        }
        roles = Set.copyOf(roles);
        permissions = Set.copyOf(permissions);
    }

    public boolean hasRole(String role) {
        throw new UnsupportedOperationException("not implemented");
    }

    public boolean hasPermission(String permission) {
        throw new UnsupportedOperationException("not implemented");
    }

    public boolean isService() {
        throw new UnsupportedOperationException("not implemented");
    }
}
