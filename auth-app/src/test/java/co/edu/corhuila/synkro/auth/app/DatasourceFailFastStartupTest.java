package co.edu.corhuila.synkro.auth.app;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.context.ConfigurableApplicationContext;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

/**
 * Same discipline as {@link FailFastStartupTest} for the signing key: the service refuses to
 * start without a usable datasource, says which variable is wrong, and never prints the password.
 */
@ExtendWith(OutputCaptureExtension.class)
class DatasourceFailFastStartupTest {

    private static final String URL = "jdbc:postgresql://db.invalid:5432/synkro?currentSchema=auth_schema";
    private static final String SECRET = "secret-" + UUID.randomUUID();

    @TempDir
    Path dir;

    private List<String> baseArgs() throws Exception {
        return new ArrayList<>(List.of(
            "--JWT_PRIVATE_KEY_FILE=" + TestKeys.writePrivateKeyPem(TestKeys.generate(2048), dir),
            "--server.port=0"));
    }

    private Throwable startFailure(String... datasourceArgs) throws Exception {
        List<String> args = baseArgs();
        args.addAll(List.of(datasourceArgs));
        return catchThrowable(() -> start(args).close());
    }

    private static ConfigurableApplicationContext start(List<String> args) {
        return new SpringApplicationBuilder(AuthApiApplication.class)
            .web(WebApplicationType.SERVLET)
            .run(args.toArray(String[]::new));
    }

    private static String causesOf(Throwable failure) {
        StringBuilder text = new StringBuilder();
        for (Throwable t = failure; t != null; t = t.getCause()) {
            text.append(t).append('\n');
        }
        return text.toString();
    }

    private void assertFailsNaming(Throwable failure, String variable) {
        assertThat(failure).as("startup must fail").isNotNull();
        assertThat(causesOf(failure)).contains(variable).doesNotContain(SECRET);
    }

    @Test
    void refusesToStart_whenTheUrlIsMissing() throws Exception {
        assertFailsNaming(startFailure("--spring.datasource.url=", "--spring.datasource.username=auth_app",
            "--spring.datasource.password=" + SECRET), "SPRING_DATASOURCE_URL");
    }

    @Test
    void refusesToStart_whenTheUsernameIsMissing() throws Exception {
        assertFailsNaming(startFailure("--spring.datasource.url=" + URL, "--spring.datasource.username=",
            "--spring.datasource.password=" + SECRET), "SPRING_DATASOURCE_USERNAME");
    }

    @Test
    void refusesToStart_whenThereIsNoPassword() throws Exception {
        assertFailsNaming(startFailure("--spring.datasource.url=" + URL, "--spring.datasource.username=auth_app",
            "--spring.datasource.password="), "SPRING_DATASOURCE_PASSWORD");
    }

    @Test
    void refusesToStart_whenTheUrlIsNotPostgreSql() throws Exception {
        assertFailsNaming(startFailure("--spring.datasource.url=jdbc:mysql://db.invalid/x",
            "--spring.datasource.username=auth_app", "--spring.datasource.password=" + SECRET), "SPRING_DATASOURCE_URL");
    }

    @Test
    void refusesToStart_whenTheServiceWouldConnectAsAnotherUser() throws Exception {
        for (String other : new String[] {"auth_reader", "postgres"}) {
            assertFailsNaming(startFailure("--spring.datasource.url=" + URL, "--spring.datasource.username=" + other,
                "--spring.datasource.password=" + SECRET), "auth_app");
        }
    }

    @Test
    void refusesToStart_whenThePasswordFileDoesNotExist() throws Exception {
        assertFailsNaming(startFailure("--spring.datasource.url=" + URL, "--spring.datasource.username=auth_app",
            "--spring.datasource.password=", "--spring.datasource.password-file=" + dir.resolve("absent")),
            "SPRING_DATASOURCE_PASSWORD_FILE");
    }

    @Test
    void refusesToStart_whenBothThePasswordAndItsFileAreGiven() throws Exception {
        Path file = Files.writeString(dir.resolve("password"), SECRET + "\n");

        assertFailsNaming(startFailure("--spring.datasource.url=" + URL, "--spring.datasource.username=auth_app",
            "--spring.datasource.password=" + SECRET, "--spring.datasource.password-file=" + file),
            "SPRING_DATASOURCE_PASSWORD");
    }

    @Test
    void startsWithThePasswordFromAFile_andNeverLogsIt(CapturedOutput output) throws Exception {
        Path file = Files.writeString(dir.resolve("password"), SECRET + "\n");
        List<String> args = baseArgs();
        args.addAll(List.of("--spring.datasource.url=" + URL, "--spring.datasource.username=auth_app",
            "--spring.datasource.password-file=" + file));

        try (ConfigurableApplicationContext context = start(args)) {
            assertThat(context.isRunning()).isTrue();
        }
        assertThat(output.getAll()).doesNotContain(SECRET);
    }
}
