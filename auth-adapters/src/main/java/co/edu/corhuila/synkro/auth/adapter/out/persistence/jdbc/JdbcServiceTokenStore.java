package co.edu.corhuila.synkro.auth.adapter.out.persistence.jdbc;

import co.edu.corhuila.synkro.auth.application.port.out.ServiceTokenStore;
import co.edu.corhuila.synkro.auth.application.usecase.BusinessRuleViolationException;
import co.edu.corhuila.synkro.auth.domain.model.ServiceToken;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.support.TransactionOperations;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository over auth_schema.service_token and auth_schema.idempotency_key. The metadata and its key
 * are written in one transaction, started here so the use case stays free of Spring. The signed token
 * is never an input: there is no column for it. Rows are never deleted, since the service user has no
 * DELETE; a failed issuance is undone by the rollback.
 */
public class JdbcServiceTokenStore implements ServiceTokenStore {

    private static final String KEY_FIELD = "Idempotency-Key";

    private static final String FIND_BY_KEY =
        "SELECT " + ServiceTokenRows.COLUMNS + " FROM auth_schema.idempotency_key k "
            + "JOIN auth_schema.service_token t ON t.token_id = k.resource_id "
            + "WHERE k.key = ? AND k.resource_type = 'SERVICE_TOKEN'";

    // The key is claimed before the metadata is written. A concurrent request with the same key waits on
    // the primary key until this transaction ends, then finds the key taken and reads its token, so
    // exactly one of them creates. If the metadata insert fails, the rollback releases the key as well.
    private static final String CLAIM_KEY =
        "INSERT INTO auth_schema.idempotency_key (key, resource_type, resource_id) VALUES (?, 'SERVICE_TOKEN', ?) "
            + "ON CONFLICT (key) DO NOTHING";

    private static final String INSERT_TOKEN =
        "INSERT INTO auth_schema.service_token (token_id, service, permissions, issued_by, issued_at, expires_at) "
            + "VALUES (?, ?, ?, ?, ?, ?)";

    private final JdbcTemplate jdbc;
    private final TransactionOperations transactions;

    public JdbcServiceTokenStore(JdbcTemplate jdbc, TransactionOperations transactions) {
        this.jdbc = jdbc;
        this.transactions = transactions;
    }

    @Override
    public Optional<ServiceToken> findByIdempotencyKey(String idempotencyKey) {
        return jdbc.query(FIND_BY_KEY, ServiceTokenRows.TO_TOKEN, idempotencyKey).stream().findFirst();
    }

    @Override
    public Issued issueOnce(String idempotencyKey, ServiceToken token) {
        return transactions.execute(status -> {
            if (jdbc.update(CLAIM_KEY, idempotencyKey, UUID.fromString(token.tokenId())) == 0) {
                ServiceToken original = findByIdempotencyKey(idempotencyKey).orElseThrow(() ->
                    new BusinessRuleViolationException(KEY_FIELD, "The Idempotency-Key was already used by another operation"));
                return new Issued(original, false);
            }
            insert(token);
            return new Issued(token, true);
        });
    }

    private void insert(ServiceToken token) {
        jdbc.update(INSERT_TOKEN, statement -> {
            statement.setObject(1, UUID.fromString(token.tokenId()));
            statement.setString(2, token.service());
            statement.setArray(3, statement.getConnection().createArrayOf("text", token.permissions().toArray()));
            statement.setObject(4, UUID.fromString(token.issuedBy()));
            statement.setObject(5, OffsetDateTime.ofInstant(token.issuedAt(), ZoneOffset.UTC));
            statement.setObject(6, OffsetDateTime.ofInstant(token.expiresAt(), ZoneOffset.UTC));
        });
    }
}
