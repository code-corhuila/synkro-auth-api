package co.edu.corhuila.synkro.auth.app;

import co.edu.corhuila.synkro.auth.application.usecase.RoleGuard;
import co.edu.corhuila.synkro.auth.domain.model.AuthenticatedCaller;
import co.edu.corhuila.synkro.auth.domain.model.Roles;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.TreeSet;

/**
 * Test-only protected routes, never shipped (it lives in test sources). They exercise the
 * real filter chain until the first real protected endpoint exists (HU-AUTH-09). The role
 * decision is taken by {@link RoleGuard}, the way a use case takes it; the controller only
 * hands over the caller.
 */
@RestController
@RequestMapping("/test-probe")
class ProbeController {

    @GetMapping("/admin-only")
    ResponseEntity<Map<String, Object>> adminOnly(@AuthenticationPrincipal AuthenticatedCaller caller) {
        RoleGuard.requireAnyRole(caller, "read the admin probe", Roles.ADMIN);
        return describe(caller);
    }

    @GetMapping("/people-only")
    ResponseEntity<Map<String, Object>> peopleOnly(@AuthenticationPrincipal AuthenticatedCaller caller) {
        RoleGuard.requireAnyRole(caller, "read the people probe", Roles.ADMIN, Roles.SALESPERSON, Roles.INVENTORY);
        return describe(caller);
    }

    @GetMapping("/whoami")
    ResponseEntity<Map<String, Object>> whoami(@AuthenticationPrincipal AuthenticatedCaller caller) {
        return describe(caller);
    }

    @GetMapping("/framework-denied")
    ResponseEntity<Void> frameworkDenied() {
        throw new AccessDeniedException("denied by the framework");
    }

    private static ResponseEntity<Map<String, Object>> describe(AuthenticatedCaller caller) {
        return ResponseEntity.ok(Map.of(
            "subject", caller.subject(),
            "roles", new TreeSet<>(caller.roles()),
            "permissions", new TreeSet<>(caller.permissions())));
    }
}
