package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.port.out.UserRepository;
import co.edu.corhuila.synkro.auth.domain.model.AuthenticatedCaller;
import co.edu.corhuila.synkro.auth.domain.model.SystemUser;

public class GetUserUseCase {

    public GetUserUseCase(UserRepository users) {
    }

    public SystemUser execute(AuthenticatedCaller caller, String userId) {
        throw new UnsupportedOperationException("not implemented yet");
    }
}
