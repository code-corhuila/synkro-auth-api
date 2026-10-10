package co.edu.corhuila.synkro.auth.adapter.out.persistence.jdbc;

import co.edu.corhuila.synkro.auth.application.port.out.RefreshTokenStore;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.Instant;
import java.util.Optional;

public class JdbcRefreshTokenStore implements RefreshTokenStore {

    public JdbcRefreshTokenStore(JdbcTemplate jdbc) {
    }

    @Override
    public void save(String tokenHash, String userId, Instant expiresAt) {
        throw new UnsupportedOperationException("not implemented");
    }

    @Override
    public Optional<String> consumeAndRotate(String tokenHash) {
        throw new UnsupportedOperationException("not implemented");
    }
}
