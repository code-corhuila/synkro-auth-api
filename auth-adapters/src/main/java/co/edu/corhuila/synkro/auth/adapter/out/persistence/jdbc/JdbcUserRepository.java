package co.edu.corhuila.synkro.auth.adapter.out.persistence.jdbc;

import co.edu.corhuila.synkro.auth.application.port.out.UserRepository;
import co.edu.corhuila.synkro.auth.domain.model.SystemUser;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

import java.util.Optional;
import java.util.UUID;

/** Repository over auth_schema.system_user: read-only here, registration arrives with HU-AUTH-09. */
public class JdbcUserRepository implements UserRepository {

    private static final String SELECT_USER =
        "SELECT user_id::text, name, email, password_hash, role, active FROM auth_schema.system_user ";
    private static final String BY_EMAIL = SELECT_USER + "WHERE email = ?";
    private static final String BY_ID = SELECT_USER + "WHERE user_id = ?";

    private static final RowMapper<SystemUser> TO_USER = (rs, row) -> new SystemUser(
        rs.getString("user_id"), rs.getString("name"), rs.getString("email"),
        rs.getString("password_hash"), rs.getString("role"), rs.getBoolean("active"));

    private final JdbcTemplate jdbc;

    public JdbcUserRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public Optional<SystemUser> findByEmail(String email) {
        return jdbc.query(BY_EMAIL, TO_USER, email).stream().findFirst();
    }

    @Override
    public Optional<SystemUser> findById(String userId) {
        return parseUuid(userId).flatMap(id -> jdbc.query(BY_ID, TO_USER, id).stream().findFirst());
    }

    private static Optional<UUID> parseUuid(String value) {
        try {
            return Optional.of(UUID.fromString(value));
        } catch (IllegalArgumentException | NullPointerException e) {
            return Optional.empty();
        }
    }
}
