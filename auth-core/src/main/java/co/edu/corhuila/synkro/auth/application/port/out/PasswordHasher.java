package co.edu.corhuila.synkro.auth.application.port.out;

public interface PasswordHasher {
    String hash(String plaintext);

    boolean matches(String plaintext, String hash);
}
