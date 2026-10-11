package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.port.out.ServiceTokenRepository;
import co.edu.corhuila.synkro.auth.domain.model.AuthenticatedCaller;
import co.edu.corhuila.synkro.auth.domain.model.Roles;
import co.edu.corhuila.synkro.auth.domain.model.ServiceToken;

public class GetServiceTokenUseCase {
    private final ServiceTokenRepository tokens;

    public GetServiceTokenUseCase(ServiceTokenRepository tokens) {
        this.tokens = tokens;
    }

    public ServiceToken execute(AuthenticatedCaller caller, String tokenId) {
        RoleGuard.requireAnyRole(caller, "read service tokens", Roles.ADMIN);
        return tokens.findById(tokenId).orElseThrow(() -> new NotFoundException("Resource not found"));
    }
}
