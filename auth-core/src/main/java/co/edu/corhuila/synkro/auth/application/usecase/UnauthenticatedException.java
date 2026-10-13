package co.edu.corhuila.synkro.auth.application.usecase;

/** There is no verified caller: the operation needs one and must not run without it. */
public class UnauthenticatedException extends RuntimeException {
    public UnauthenticatedException() {
        super("A verified caller is required");
    }
}
