package co.edu.corhuila.synkro.auth.adapter.out.persistence.jdbc;

import co.edu.corhuila.synkro.auth.application.port.out.UserRepository;
import co.edu.corhuila.synkro.auth.domain.model.SystemUser;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.Optional;

public class JdbcUserRepository implements UserRepository {

    public JdbcUserRepository(JdbcTemplate jdbc) {
    }

    @Override
    public Optional<SystemUser> findByEmail(String email) {
        throw new UnsupportedOperationException("not implemented");
    }

    @Override
    public Optional<SystemUser> findById(String userId) {
        throw new UnsupportedOperationException("not implemented");
    }
}
