package co.edu.corhuila.synkro.auth.adapter.out.persistence.jdbc;

import co.edu.corhuila.synkro.auth.domain.model.SystemUser;
import org.springframework.jdbc.core.RowMapper;

import java.time.OffsetDateTime;

/** How a row of auth_schema.system_user, read with {@link #COLUMNS}, becomes a SystemUser. */
final class SystemUserRows {
    static final String COLUMNS =
        "u.user_id::text AS user_id, u.name, u.email, u.password_hash, u.role, u.registration_date, u.active";

    static final RowMapper<SystemUser> TO_USER = (rs, row) -> new SystemUser(
        rs.getString("user_id"), rs.getString("name"), rs.getString("email"),
        rs.getString("password_hash"), rs.getString("role"),
        rs.getObject("registration_date", OffsetDateTime.class).toInstant(), rs.getBoolean("active"));

    private SystemUserRows() {}
}
