package co.edu.corhuila.synkro.auth.adapter.out.persistence.inmemory;

import co.edu.corhuila.synkro.auth.application.port.out.RefreshTokenStore;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * TEMPORARY. Replaced by a real Postgres adapter once synkro-auth-db has a
 * refresh_token table.
 *
 * Holds hashed refresh tokens in process memory only: they are lost on restart and
 * not shared between instances, which is fine for proving the rotation contract and
 * wrong for anything real. It implements the one-time-use contract of the port, and
 * does so atomically, so two concurrent replays of the same token cannot both win.
 */
public class InMemoryRefreshTokenStore implements RefreshTokenStore {

    private final Map<String, String> userIdByTokenHash = new ConcurrentHashMap<>();

    @Override
    public void save(String tokenHash, String userId) {
        userIdByTokenHash.put(tokenHash, userId);
    }

    @Override
    public Optional<String> consumeAndRotate(String tokenHash) {
        // ConcurrentHashMap.remove is atomic: exactly one caller gets the value.
        return Optional.ofNullable(userIdByTokenHash.remove(tokenHash));
    }
}
