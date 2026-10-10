package co.edu.corhuila.synkro.auth.adapter.out.crypto;

import co.edu.corhuila.synkro.auth.application.port.out.AccessTokenVerifier;
import co.edu.corhuila.synkro.auth.domain.model.AuthenticatedCaller;

import java.security.PublicKey;
import java.time.Clock;

public class Rs256TokenVerifier implements AccessTokenVerifier {

    public Rs256TokenVerifier(PublicKey publicKey, Clock clock) {
    }

    @Override
    public AuthenticatedCaller verify(String token) {
        throw new UnsupportedOperationException("not implemented");
    }
}
