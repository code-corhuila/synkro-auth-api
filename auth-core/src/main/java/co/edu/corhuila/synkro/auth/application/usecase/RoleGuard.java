package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.domain.model.AuthenticatedCaller;

import java.util.Arrays;
import java.util.Set;
import java.util.TreeSet;

/**
 * Guard clause the use cases call before doing any work: the role or permission decision
 * lives in the application layer, never in the controller (security-rules.md, A01).
 */
public final class RoleGuard {
    private RoleGuard() {}

    public static void requireAnyRole(AuthenticatedCaller caller, String operation, String... roles) {
        if (Arrays.stream(roles).noneMatch(caller::hasRole)) {
            throw forbidden(caller, operation);
        }
    }

    public static void requirePermission(AuthenticatedCaller caller, String operation, String permission) {
        if (!caller.hasPermission(permission)) {
            throw forbidden(caller, operation);
        }
    }

    private static ForbiddenException forbidden(AuthenticatedCaller caller, String operation) {
        return new ForbiddenException("Role " + describe(caller.roles()) + " is not authorized to " + operation);
    }

    private static String describe(Set<String> roles) {
        return roles.isEmpty() ? "(none)" : String.join(", ", new TreeSet<>(roles));
    }
}
