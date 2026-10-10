package co.edu.corhuila.synkro.auth.app;

import co.edu.corhuila.synkro.auth.application.port.out.RefreshTokenStore;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/** Test double honouring the port's contract: one use per token, nothing after its expiry. */
class FakeRefreshTokenStore implements RefreshTokenStore {

    private record Entry(String userId, Instant expiresAt) {}

    private final Map<String, Entry> byHash = new ConcurrentHashMap<>();

    @Override
    public void save(String tokenHash, String userId, Instant expiresAt) {
        byHash.put(tokenHash, new Entry(userId, expiresAt));
    }

    @Override
    public Optional<String> consumeAndRotate(String tokenHash) {
        return Optional.ofNullable(byHash.remove(tokenHash))
            .filter(entry -> entry.expiresAt().isAfter(Instant.now()))
            .map(Entry::userId);
    }
}
