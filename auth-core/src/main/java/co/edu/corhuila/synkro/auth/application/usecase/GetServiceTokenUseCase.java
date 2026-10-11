package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.port.out.ServiceTokenRepository;
import co.edu.corhuila.synkro.auth.domain.model.AuthenticatedCaller;
import co.edu.corhuila.synkro.auth.domain.model.ServiceToken;

public class GetServiceTokenUseCase {
    private final ServiceTokenRepository tokens;

    public GetServiceTokenUseCase(ServiceTokenRepository tokens) {
        this.tokens = tokens;
    }

    public ServiceToken execute(AuthenticatedCaller caller, String tokenId) {
        throw new UnsupportedOperationException("not implemented");
    }
}
