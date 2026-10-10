package co.edu.corhuila.synkro.auth.application.usecase;

/** Carries no detail about why: a missing, malformed, expired or forged token is the same 401 to the caller. */
public class InvalidTokenException extends RuntimeException {
    public InvalidTokenException() {
        super("invalid token");
    }

    public InvalidTokenException(Throwable cause) {
        super("invalid token", cause);
    }
}
