package co.edu.corhuila.synkro.auth.app;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/** Throwaway RSA key material for tests; nothing here is ever a real credential. */
final class TestKeys {
    private TestKeys() {}

    static KeyPair generate(int bits) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(bits);
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** Writes the private key as PKCS#8 PEM ("BEGIN PRIVATE KEY"), the format JWT_PRIVATE_KEY_FILE expects. */
    static Path writePrivateKeyPem(KeyPair pair, Path dir) throws Exception {
        String pem = "-----BEGIN PRIVATE KEY-----\n"
            + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(pair.getPrivate().getEncoded())
            + "\n-----END PRIVATE KEY-----\n";
        return Files.writeString(Files.createTempFile(dir, "jwt-private", ".pem"), pem);
    }

    /** Parses an X.509 "BEGIN PUBLIC KEY" PEM, the form services receive as JWT_PUBLIC_KEY. */
    static PublicKey parsePublicKeyPem(String pem) throws Exception {
        String body = pem.replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replaceAll("\\s", "");
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(body)));
    }

    static String publicKeyPem(KeyPair pair) {
        return "-----BEGIN PUBLIC KEY-----\n"
            + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(pair.getPublic().getEncoded())
            + "\n-----END PUBLIC KEY-----\n";
    }
}
