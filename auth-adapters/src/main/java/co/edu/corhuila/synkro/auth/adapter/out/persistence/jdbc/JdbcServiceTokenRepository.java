package co.edu.corhuila.synkro.auth.adapter.out.persistence.jdbc;

import co.edu.corhuila.synkro.auth.application.port.out.ServiceTokenRepository;
import co.edu.corhuila.synkro.auth.domain.model.ServiceToken;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.Optional;
import java.util.UUID;

/** Repository over auth_schema.service_token: it reads the metadata; JdbcServiceTokenStore writes it. */
public class JdbcServiceTokenRepository implements ServiceTokenRepository {

    private static final String BY_ID =
        "SELECT " + ServiceTokenRows.COLUMNS + " FROM auth_schema.service_token t WHERE t.token_id = ?";

    private final JdbcTemplate jdbc;

    public JdbcServiceTokenRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public Optional<ServiceToken> findById(String tokenId) {
        return parseUuid(tokenId).flatMap(id -> jdbc.query(BY_ID, ServiceTokenRows.TO_TOKEN, id).stream().findFirst());
    }

    private static Optional<UUID> parseUuid(String value) {
        try {
            return Optional.of(UUID.fromString(value));
        } catch (IllegalArgumentException | NullPointerException e) {
            return Optional.empty();
        }
    }
}
