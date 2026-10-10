package co.edu.corhuila.synkro.auth.adapter.out.persistence.jdbc;

import co.edu.corhuila.synkro.auth.application.port.out.UserRepository;
import co.edu.corhuila.synkro.auth.domain.model.SystemUser;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.Optional;
import java.util.UUID;

/** Repository over auth_schema.system_user: it reads users; JdbcUserRegistrationStore writes them. */
public class JdbcUserRepository implements UserRepository {

    private static final String SELECT_USER =
        "SELECT " + SystemUserRows.COLUMNS + " FROM auth_schema.system_user u ";
    private static final String BY_EMAIL = SELECT_USER + "WHERE u.email = ?";
    private static final String BY_ID = SELECT_USER + "WHERE u.user_id = ?";

    private final JdbcTemplate jdbc;

    public JdbcUserRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public Optional<SystemUser> findByEmail(String email) {
        return jdbc.query(BY_EMAIL, SystemUserRows.TO_USER, email).stream().findFirst();
    }

    @Override
    public Optional<SystemUser> findById(String userId) {
        return parseUuid(userId).flatMap(id -> jdbc.query(BY_ID, SystemUserRows.TO_USER, id).stream().findFirst());
    }

    private static Optional<UUID> parseUuid(String value) {
        try {
            return Optional.of(UUID.fromString(value));
        } catch (IllegalArgumentException | NullPointerException e) {
            return Optional.empty();
        }
    }
}
