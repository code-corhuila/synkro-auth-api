package co.edu.corhuila.synkro.auth.application.port.out;

public interface PasswordHasher {
    boolean matches(String plaintext, String hash);
}
