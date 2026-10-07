package co.edu.corhuila.synkro.auth.application.usecase;

/**
 * Deliberately carries no detail: unknown email, inactive user, wrong password and
 * a bad refresh token must be indistinguishable to the caller.
 */
public class InvalidCredentialsException extends RuntimeException {
    public InvalidCredentialsException() {
        super("invalid credentials");
    }
}
