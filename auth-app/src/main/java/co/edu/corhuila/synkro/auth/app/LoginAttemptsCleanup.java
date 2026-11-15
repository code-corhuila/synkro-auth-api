package co.edu.corhuila.synkro.auth.app;

import co.edu.corhuila.synkro.auth.adapter.out.memory.MemoryLoginAttempts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import java.time.Clock;

@Component
public final class LoginAttemptsCleanup {
    private final MemoryLoginAttempts attempts;
    private final Clock clock;
    private final long retention;
    public LoginAttemptsCleanup(MemoryLoginAttempts attempts,Clock clock,
            @Value("${synkro.auth.login-retention-seconds:600}") long retention) {
        this.attempts=attempts;this.clock=clock;this.retention=retention;
    }
    @Scheduled(fixedDelayString="${synkro.auth.login-cleanup-ms:30000}")
    public void removeExpired(){attempts.removeExpired(clock.instant().minusSeconds(retention));}
}
