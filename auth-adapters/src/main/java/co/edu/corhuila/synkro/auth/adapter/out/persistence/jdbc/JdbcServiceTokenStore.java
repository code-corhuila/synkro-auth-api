package co.edu.corhuila.synkro.auth.adapter.out.persistence.jdbc;

import co.edu.corhuila.synkro.auth.application.port.out.ServiceTokenStore;
import co.edu.corhuila.synkro.auth.domain.model.ServiceToken;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.support.TransactionOperations;

import java.util.Optional;

public class JdbcServiceTokenStore implements ServiceTokenStore {

    private final JdbcTemplate jdbc;
    private final TransactionOperations transactions;

    public JdbcServiceTokenStore(JdbcTemplate jdbc, TransactionOperations transactions) {
        this.jdbc = jdbc;
        this.transactions = transactions;
    }

    @Override
    public Optional<ServiceToken> findByIdempotencyKey(String idempotencyKey) {
        return Optional.empty();
    }

    @Override
    public Issued issueOnce(String idempotencyKey, ServiceToken token) {
        throw new UnsupportedOperationException("not implemented");
    }
}
