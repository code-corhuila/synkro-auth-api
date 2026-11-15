package co.edu.corhuila.synkro.auth.application.usecase;

public final class LoginThrottledException extends RuntimeException {
    private final long retryAfterSeconds;
    public LoginThrottledException(long retryAfterSeconds) {
        super("Too many authentication requests; retry later");
        this.retryAfterSeconds = retryAfterSeconds;
    }
    public long retryAfterSeconds() { return retryAfterSeconds; }
}
