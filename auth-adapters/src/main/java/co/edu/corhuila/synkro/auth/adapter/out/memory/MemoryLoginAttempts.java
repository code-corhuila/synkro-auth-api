package co.edu.corhuila.synkro.auth.adapter.out.memory;

import co.edu.corhuila.synkro.auth.application.port.out.LoginAttemptStore;
import co.edu.corhuila.synkro.auth.application.usecase.LoginThrottledException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Function;

/** Bounded process-local state. Only allocation/cleanup holds the map monitor; verification locks its own entry. */
public final class MemoryLoginAttempts implements LoginAttemptStore {
    private final Map<String,Entry> accounts = new HashMap<>();
    private final int capacity;

    public MemoryLoginAttempts(int capacity) {
        if (capacity < 1) throw new IllegalArgumentException("Account capacity must be positive");
        this.capacity = capacity;
    }

    public <T> T compute(String key, Function<State,Update<T>> action) {
        Entry entry;
        synchronized (accounts) {
            entry = accounts.get(key);
            if (entry == null) {
                if (accounts.size() >= capacity) throw new LoginThrottledException(1);
                entry = new Entry();
                accounts.put(key,entry);
            }
            entry.users++;
        }
        entry.lock.lock();
        try {
            Update<T> update = action.apply(entry.state);
            entry.state = update.state();
            return update.result();
        } finally {
            entry.lock.unlock();
            synchronized (accounts) {
                entry.users--;
                if (entry.users == 0 && entry.state == null) accounts.remove(key,entry);
            }
        }
    }

    public void removeExpired(Instant cutoff) {
        synchronized (accounts) {
            accounts.entrySet().removeIf(row -> {
                Entry entry = row.getValue();
                return entry.users == 0 && entry.state != null && !entry.state.evaluatedAt().isAfter(cutoff);
            });
        }
    }

    public int retainedAccounts() {
        synchronized (accounts) { return accounts.size(); }
    }

    private static final class Entry {
        private final ReentrantLock lock = new ReentrantLock();
        private volatile State state;
        private int users;
    }
}
