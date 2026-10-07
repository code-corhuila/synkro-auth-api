package co.edu.corhuila.synkro.auth.app;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;

import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The service must refuse to start without a usable signing key, the same
 * fail-fast discipline synkro-worker applies to its own required credential.
 * Each failure case also asserts the cause names JWT_PRIVATE_KEY_FILE, so the
 * test cannot pass because of some unrelated startup error.
 */
class FailFastStartupTest {

    @TempDir
    Path dir;

    private ConfigurableApplicationContext start(String... args) {
        return new SpringApplicationBuilder(AuthApiApplication.class)
            .web(WebApplicationType.SERVLET)
            .run(concat(args, "--server.port=0"));
    }

    private static String[] concat(String[] args, String extra) {
        String[] all = java.util.Arrays.copyOf(args, args.length + 1);
        all[args.length] = extra;
        return all;
    }

    @Test
    void refusesToStart_whenTheKeyFileVariableIsUnset() {
        Assumptions.assumeTrue(System.getenv("JWT_PRIVATE_KEY_FILE") == null,
            "JWT_PRIVATE_KEY_FILE is set in this shell, so 'unset' cannot be exercised");

        assertThatThrownBy(() -> start())
            .hasStackTraceContaining("JWT_PRIVATE_KEY_FILE");
    }

    @Test
    void refusesToStart_whenTheKeyFileVariableIsBlank() {
        assertThatThrownBy(() -> start("--JWT_PRIVATE_KEY_FILE="))
            .hasStackTraceContaining("JWT_PRIVATE_KEY_FILE");
    }

    @Test
    void refusesToStart_whenTheKeyFileDoesNotExist() {
        String missing = dir.resolve("absent.pem").toString();

        assertThatThrownBy(() -> start("--JWT_PRIVATE_KEY_FILE=" + missing))
            .hasStackTraceContaining("JWT_PRIVATE_KEY_FILE");
    }

    @Test
    void startsNormally_withAValidKeyFile() throws Exception {
        Path key = TestKeys.writePrivateKeyPem(TestKeys.generate(2048), dir);

        try (ConfigurableApplicationContext context = start("--JWT_PRIVATE_KEY_FILE=" + key)) {
            assertThat(context.isRunning()).isTrue();
        }
    }
}
