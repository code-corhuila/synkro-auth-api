package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.port.out.UserRepository;
import co.edu.corhuila.synkro.auth.domain.model.AuthenticatedCaller;
import co.edu.corhuila.synkro.auth.domain.model.Roles;
import co.edu.corhuila.synkro.auth.domain.model.SystemUser;

public class GetUserUseCase {
    private final UserRepository users;

    public GetUserUseCase(UserRepository users) {
        this.users = users;
    }

    public SystemUser execute(AuthenticatedCaller caller, String userId) {
        RoleGuard.requireAnyRole(caller, "read users", Roles.ADMIN);
        return users.findById(userId).orElseThrow(() -> new NotFoundException("Resource not found"));
    }
}
