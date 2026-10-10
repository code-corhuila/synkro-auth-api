package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.domain.model.AuthenticatedCaller;

public final class RoleGuard {
    private RoleGuard() {}

    public static void requireAnyRole(AuthenticatedCaller caller, String operation, String... roles) {
        throw new UnsupportedOperationException("not implemented");
    }

    public static void requirePermission(AuthenticatedCaller caller, String operation, String permission) {
        throw new UnsupportedOperationException("not implemented");
    }
}
