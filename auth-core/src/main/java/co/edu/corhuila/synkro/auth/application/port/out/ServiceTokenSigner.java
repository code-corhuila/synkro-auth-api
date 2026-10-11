package co.edu.corhuila.synkro.auth.application.port.out;

import co.edu.corhuila.synkro.auth.domain.model.ServiceToken;

public interface ServiceTokenSigner {
    String sign(ServiceToken token);
}
