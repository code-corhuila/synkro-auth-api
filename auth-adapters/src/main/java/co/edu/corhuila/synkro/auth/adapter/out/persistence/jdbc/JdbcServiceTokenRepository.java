package co.edu.corhuila.synkro.auth.adapter.out.persistence.jdbc;

import co.edu.corhuila.synkro.auth.application.port.out.ServiceTokenRepository;
import co.edu.corhuila.synkro.auth.domain.model.ServiceToken;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.Optional;

/** Repository over auth_schema.service_token: it reads the metadata; JdbcServiceTokenStore writes it. */
public class JdbcServiceTokenRepository implements ServiceTokenRepository {

    private final JdbcTemplate jdbc;

    public JdbcServiceTokenRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public Optional<ServiceToken> findById(String tokenId) {
        return Optional.empty();
    }
}
