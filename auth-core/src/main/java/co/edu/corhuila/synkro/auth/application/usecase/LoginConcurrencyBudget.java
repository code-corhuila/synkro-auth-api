package co.edu.corhuila.synkro.auth.application.usecase;

import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;

public final class LoginConcurrencyBudget {
    private final Semaphore slots;
    private final int retrySeconds;
    public LoginConcurrencyBudget(int capacity, int retrySeconds) {
        if (capacity < 1 || retrySeconds < 1) throw new IllegalArgumentException("Login capacity and retry must be positive");
        this.slots = new Semaphore(capacity);
        this.retrySeconds = retrySeconds;
    }
    public Permit acquire() {
        if (!slots.tryAcquire()) throw new LoginThrottledException(retrySeconds);
        return new Permit(slots);
    }
    public static final class Permit implements AutoCloseable {
        private final Semaphore slots;
        private final AtomicBoolean closed = new AtomicBoolean();
        private Permit(Semaphore slots) { this.slots = slots; }
        public void close() { if (closed.compareAndSet(false, true)) slots.release(); }
    }
}
