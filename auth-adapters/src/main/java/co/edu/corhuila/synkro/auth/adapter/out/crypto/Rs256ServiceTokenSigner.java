package co.edu.corhuila.synkro.auth.adapter.out.crypto;

import co.edu.corhuila.synkro.auth.application.port.out.ServiceTokenSigner;
import co.edu.corhuila.synkro.auth.domain.model.ServiceToken;

import java.security.PrivateKey;

public class Rs256ServiceTokenSigner implements ServiceTokenSigner {
    private final PrivateKey privateKey;

    public Rs256ServiceTokenSigner(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    @Override
    public String sign(ServiceToken token) {
        throw new UnsupportedOperationException("not implemented");
    }
}
