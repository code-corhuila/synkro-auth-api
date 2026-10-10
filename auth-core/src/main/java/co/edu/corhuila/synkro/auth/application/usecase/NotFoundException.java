package co.edu.corhuila.synkro.auth.application.usecase;

/** The resource does not exist; it carries no detail about what was looked for. */
public class NotFoundException extends RuntimeException {
    public NotFoundException(String message) {
        super(message);
    }
}
