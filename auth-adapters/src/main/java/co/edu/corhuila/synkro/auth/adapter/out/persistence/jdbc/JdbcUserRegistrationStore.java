package co.edu.corhuila.synkro.auth.adapter.out.persistence.jdbc;

import co.edu.corhuila.synkro.auth.application.port.out.UserRegistrationStore;
import co.edu.corhuila.synkro.auth.domain.model.SystemUser;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.support.TransactionOperations;

import java.util.Optional;

/** Repository over auth_schema.system_user and auth_schema.idempotency_key, written in one transaction. */
public class JdbcUserRegistrationStore implements UserRegistrationStore {

    public JdbcUserRegistrationStore(JdbcTemplate jdbc, TransactionOperations transactions) {
    }

    @Override
    public Optional<SystemUser> findByIdempotencyKey(String idempotencyKey) {
        throw new UnsupportedOperationException("not implemented yet");
    }

    @Override
    public Registered registerOnce(String idempotencyKey, SystemUser user) {
        throw new UnsupportedOperationException("not implemented yet");
    }
}
