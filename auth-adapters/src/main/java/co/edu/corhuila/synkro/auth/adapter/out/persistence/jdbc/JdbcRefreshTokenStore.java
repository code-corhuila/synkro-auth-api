package co.edu.corhuila.synkro.auth.adapter.out.persistence.jdbc;

import co.edu.corhuila.synkro.auth.application.port.out.RefreshTokenStore;
import org.springframework.jdbc.core.JdbcTemplate;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository over auth_schema.refresh_token. The token column holds the hash the use case
 * hands over, never the token. Rows are never deleted: the service user has no DELETE.
 */
public class JdbcRefreshTokenStore implements RefreshTokenStore {

    private static final String INSERT =
        "INSERT INTO auth_schema.refresh_token (user_id, token, expiration_date) VALUES (?, ?, ?)";

    // One statement decides "usable or not" and burns the token, so two concurrent callers
    // cannot both win: the second waits on the row lock, re-evaluates active = true against
    // the committed row and finds nothing.
    private static final String CONSUME =
        "UPDATE auth_schema.refresh_token SET active = false "
            + "WHERE token = ? AND active = true AND expiration_date > now() "
            + "RETURNING user_id::text";

    // Asked only after CONSUME found nothing. By then the winner of a race has committed, so an
    // inactive, unexpired row is a token that was used before: a replay.
    private static final String FIND_USED =
        "SELECT user_id::text FROM auth_schema.refresh_token "
            + "WHERE token = ? AND active = false AND expiration_date > now()";

    private final JdbcTemplate jdbc;

    public JdbcRefreshTokenStore(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public void save(String tokenHash, String userId, Instant expiresAt) {
        jdbc.update(INSERT, UUID.fromString(userId), tokenHash, Timestamp.from(expiresAt));
    }

    @Override
    public Consumption consume(String tokenHash) {
        return firstOwner(CONSUME, tokenHash).<Consumption>map(Consumption.Consumed::new)
            .or(() -> firstOwner(FIND_USED, tokenHash).map(Consumption.AlreadyUsed::new))
            .orElseGet(Consumption.Unknown::new);
    }

    private Optional<String> firstOwner(String sql, String tokenHash) {
        return jdbc.queryForList(sql, String.class, tokenHash).stream().findFirst();
    }
}
