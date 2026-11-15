package co.edu.corhuila.synkro.auth.application.port.out;
import java.time.Instant;
import java.util.List;
import java.util.function.Function;

public interface LoginAttemptStore {
    record State(List<Instant> failuresAt,int cycle,Instant blockedUntil,Instant evaluatedAt) {
        public State { failuresAt=List.copyOf(failuresAt); }
        public int failures(){return failuresAt.size();}
    }
    record Update<T>(State state,T result) {}
    /** Atomic per key, including the callback; exceptions preserve the prior state. */
    <T>T compute(String key,Function<State,Update<T>> action);
    void removeExpired(Instant cutoff);
}
