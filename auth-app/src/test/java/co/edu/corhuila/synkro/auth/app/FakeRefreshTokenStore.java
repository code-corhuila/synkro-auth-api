package co.edu.corhuila.synkro.auth.app;

import co.edu.corhuila.synkro.auth.application.port.out.RefreshTokenStore;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** Test double honouring the port's contract: one use per token, nothing after its expiry, used tokens stay known. */
class FakeRefreshTokenStore implements RefreshTokenStore {

    private record Entry(String userId, Instant expiresAt, boolean active) {
        Entry used() {
            return new Entry(userId, expiresAt, false);
        }
    }

    private final Map<String, Entry> byHash = new ConcurrentHashMap<>();

    @Override
    public void save(String tokenHash, String userId, Instant expiresAt) {
        byHash.put(tokenHash, new Entry(userId, expiresAt, true));
    }

    @Override
    public Consumption consume(String tokenHash) {
        Entry[] before = new Entry[1];
        byHash.computeIfPresent(tokenHash, (hash, entry) -> {
            before[0] = entry;
            return entry.used();
        });
        Entry entry = before[0];
        if (entry == null || !entry.expiresAt().isAfter(Instant.now())) {
            return new Consumption.Unknown();
        }
        return entry.active() ? new Consumption.Consumed(entry.userId()) : new Consumption.AlreadyUsed(entry.userId());
    }
}
