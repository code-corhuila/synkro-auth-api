package co.edu.corhuila.synkro.auth.application.port.out;

import co.edu.corhuila.synkro.auth.domain.model.ServiceToken;

import java.util.Optional;

/** Reads the metadata of issued service tokens; ServiceTokenStore writes it. */
public interface ServiceTokenRepository {

    /** Empty for an unknown id and for text that is not an identifier at all. */
    Optional<ServiceToken> findById(String tokenId);
}
