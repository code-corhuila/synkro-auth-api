package co.edu.corhuila.synkro.auth.application.usecase;

/** The caller is authenticated but its role or permissions do not allow the operation. */
public class ForbiddenException extends RuntimeException {
    public ForbiddenException(String message) {
        super(message);
    }
}
