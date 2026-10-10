package co.edu.corhuila.synkro.auth.application.port.out;

import co.edu.corhuila.synkro.auth.application.usecase.InvalidTokenException;
import co.edu.corhuila.synkro.auth.domain.model.AuthenticatedCaller;

public interface AccessTokenVerifier {
    /** Returns the caller described by the token's claims, or raises {@link InvalidTokenException} for any token it cannot trust. */
    AuthenticatedCaller verify(String token);
}
