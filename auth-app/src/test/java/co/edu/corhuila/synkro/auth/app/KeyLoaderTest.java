package co.edu.corhuila.synkro.auth.app;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class KeyLoaderTest {

    @TempDir
    Path dir;

    @Test
    void loadsAPkcs8PemPrivateKey_matchingTheOneWritten() throws Exception {
        KeyPair pair = TestKeys.generate(2048);
        Path file = TestKeys.writePrivateKeyPem(pair, dir);

        PrivateKey loaded = KeyLoader.loadPrivateKey(file.toString());

        assertThat(loaded.getAlgorithm()).isEqualTo("RSA");
        assertThat(((RSAPrivateCrtKey) loaded).getModulus())
            .isEqualTo(((RSAPrivateCrtKey) pair.getPrivate()).getModulus());
    }

    @Test
    void nullPath_failsWithAMessageNamingTheVariable() {
        assertThatThrownBy(() -> KeyLoader.loadPrivateKey(null))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("JWT_PRIVATE_KEY_FILE");
    }

    @Test
    void blankPath_failsWithAMessageNamingTheVariable() {
        assertThatThrownBy(() -> KeyLoader.loadPrivateKey("   "))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("JWT_PRIVATE_KEY_FILE");
    }

    @Test
    void missingFile_fails() {
        assertThatThrownBy(() -> KeyLoader.loadPrivateKey(dir.resolve("absent.pem").toString()))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("JWT_PRIVATE_KEY_FILE");
    }

    @Test
    void fileThatIsNotAPem_fails() throws Exception {
        Path garbage = Files.writeString(dir.resolve("garbage.pem"), "this is not a key");

        assertThatThrownBy(() -> KeyLoader.loadPrivateKey(garbage.toString()))
            .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void pkcs1PemIsRejectedWithAClearMessage() throws Exception {
        Path pkcs1 = Files.writeString(dir.resolve("pkcs1.pem"),
            "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n");

        assertThatThrownBy(() -> KeyLoader.loadPrivateKey(pkcs1.toString()))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("PKCS#8");
    }

    @Test
    void keyShorterThan2048Bits_isRejected() throws Exception {
        Path weak = TestKeys.writePrivateKeyPem(TestKeys.generate(1024), dir);

        assertThatThrownBy(() -> KeyLoader.loadPrivateKey(weak.toString()))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("2048");
    }
}
