package co.edu.corhuila.synkro.auth.application.port.out;

import co.edu.corhuila.synkro.auth.domain.model.SystemUser;

import java.util.Optional;

public interface UserRepository {
    Optional<SystemUser> findByEmail(String email);

    // Refresh only knows the userId stored beside the token hash, and needs the
    // user's current role and active flag to issue a fresh access token.
    Optional<SystemUser> findById(String userId);
}
