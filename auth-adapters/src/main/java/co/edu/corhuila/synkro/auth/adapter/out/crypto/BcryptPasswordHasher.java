package co.edu.corhuila.synkro.auth.adapter.out.crypto;

import co.edu.corhuila.synkro.auth.application.port.out.PasswordHasher;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class BcryptPasswordHasher implements PasswordHasher {
    // security-policy.md: bcrypt, cost >= 12.
    private static final int COST = 12;

    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(COST);

    public String hash(String plaintext) {
        return encoder.encode(plaintext);
    }

    @Override
    public boolean matches(String plaintext, String hash) {
        try {
            return encoder.matches(plaintext, hash);
        } catch (RuntimeException e) {
            return false;
        }
    }
}
