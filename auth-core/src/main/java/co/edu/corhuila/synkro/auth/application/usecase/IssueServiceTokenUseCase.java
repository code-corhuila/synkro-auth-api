package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.port.out.IdGenerator;
import co.edu.corhuila.synkro.auth.application.port.out.ServiceTokenSigner;
import co.edu.corhuila.synkro.auth.application.port.out.ServiceTokenStore;
import co.edu.corhuila.synkro.auth.domain.model.AuthenticatedCaller;

import java.time.Clock;

public class IssueServiceTokenUseCase {
    private final ServiceTokenStore tokens;
    private final ServiceTokenSigner signer;
    private final IdGenerator ids;
    private final Clock clock;

    public IssueServiceTokenUseCase(ServiceTokenStore tokens, ServiceTokenSigner signer, IdGenerator ids, Clock clock) {
        this.tokens = tokens;
        this.signer = signer;
        this.ids = ids;
        this.clock = clock;
    }

    public IssueServiceTokenResult execute(AuthenticatedCaller caller, IssueServiceTokenCommand command) {
        throw new UnsupportedOperationException("not implemented");
    }
}
