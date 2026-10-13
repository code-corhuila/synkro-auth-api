package co.edu.corhuila.synkro.auth.app;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.interfaces.RSAKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/**
 * Loads the RS256 signing key from the PKCS#8 PEM file named by JWT_PRIVATE_KEY_FILE.
 * Every failure is an IllegalStateException naming the variable, so a misconfigured
 * deployment stops at startup instead of failing on the first login.
 */
public class KeyLoader {
    private static final String BEGIN = "-----BEGIN PRIVATE KEY-----";
    private static final String END = "-----END PRIVATE KEY-----";
    private static final int MIN_RSA_BITS = 2048;

    private KeyLoader() {}

    public static PrivateKey loadPrivateKey(String path) {
        if (path == null || path.isBlank()) {
            throw new IllegalStateException("JWT_PRIVATE_KEY_FILE is required but is not set");
        }

        String content;
        try {
            content = Files.readString(Path.of(path));
        } catch (IOException | RuntimeException e) {
            throw new IllegalStateException("JWT_PRIVATE_KEY_FILE is not readable: " + path, e);
        }

        if (!content.contains(BEGIN)) {
            throw new IllegalStateException(
                "JWT_PRIVATE_KEY_FILE must be an unencrypted PKCS#8 PEM (\"" + BEGIN + "\"): " + path);
        }

        PrivateKey key;
        try {
            byte[] der = Base64.getDecoder().decode(content.replace(BEGIN, "").replace(END, "").replaceAll("\\s", ""));
            key = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new IllegalStateException("JWT_PRIVATE_KEY_FILE does not contain a valid RSA private key: " + path, e);
        }

        if (!(key instanceof RSAKey rsa) || rsa.getModulus().bitLength() < MIN_RSA_BITS) {
            throw new IllegalStateException("JWT_PRIVATE_KEY_FILE must hold an RSA key of at least " + MIN_RSA_BITS + " bits");
        }
        return key;
    }
}
