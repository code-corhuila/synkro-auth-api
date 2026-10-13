package co.edu.corhuila.synkro.auth.adapter.out.crypto;

import co.edu.corhuila.synkro.auth.application.port.out.HashFunction;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Plain SHA-256 is appropriate here, unlike for passwords: refresh tokens are 256 bits of
 * randomness, so there is nothing to brute-force and a slow hash would only cost latency.
 */
public class Sha256HashFunction implements HashFunction {

    @Override
    public String hash(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required on every JVM", e);
        }
    }
}
