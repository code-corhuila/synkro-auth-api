package co.edu.corhuila.synkro.auth.adapter.out.persistence.jdbc;

import co.edu.corhuila.synkro.auth.domain.model.ServiceToken;
import org.springframework.jdbc.core.RowMapper;

import java.sql.Array;
import java.sql.SQLException;
import java.time.OffsetDateTime;
import java.util.List;

/** How a row of auth_schema.service_token, read with {@link #COLUMNS}, becomes a ServiceToken. */
final class ServiceTokenRows {
    static final String COLUMNS =
        "t.token_id::text AS token_id, t.service, t.permissions, t.issued_by::text AS issued_by, t.issued_at, t.expires_at";

    static final RowMapper<ServiceToken> TO_TOKEN = (rs, row) -> new ServiceToken(
        rs.getString("token_id"), rs.getString("service"), permissionsOf(rs.getArray("permissions")),
        rs.getString("issued_by"), rs.getObject("issued_at", OffsetDateTime.class).toInstant(),
        rs.getObject("expires_at", OffsetDateTime.class).toInstant());

    private ServiceTokenRows() {}

    private static List<String> permissionsOf(Array array) throws SQLException {
        return List.of((String[]) array.getArray());
    }
}
