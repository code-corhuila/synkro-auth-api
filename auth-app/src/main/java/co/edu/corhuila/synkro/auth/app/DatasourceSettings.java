package co.edu.corhuila.synkro.auth.app;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * The validated connection settings. Every failure names the environment variable that is
 * wrong and never repeats a value: the URL may carry credentials and the password is a secret.
 */
record DatasourceSettings(String url, String username, String password) {

    static final String SERVICE_USER = "auth_app";
    private static final String URL_PREFIX = "jdbc:postgresql:";

    static DatasourceSettings resolve(String url, String username, String password, String passwordFile) {
        if (isBlank(url)) {
            throw invalid("SPRING_DATASOURCE_URL is not set: the service needs the JDBC URL of its PostgreSQL database");
        }
        if (!url.startsWith(URL_PREFIX)) {
            throw invalid("SPRING_DATASOURCE_URL must be a PostgreSQL JDBC URL (it must start with " + URL_PREFIX + ")");
        }
        if (isBlank(username)) {
            throw invalid("SPRING_DATASOURCE_USERNAME is not set: the service connects as " + SERVICE_USER);
        }
        if (!SERVICE_USER.equals(username)) {
            throw invalid("SPRING_DATASOURCE_USERNAME must be " + SERVICE_USER
                + ": the service never connects as a reader or an administrator");
        }
        return new DatasourceSettings(url, username, passwordFrom(password, passwordFile));
    }

    private static String passwordFrom(String password, String passwordFile) {
        boolean hasPassword = !isBlank(password);
        boolean hasFile = !isBlank(passwordFile);
        if (hasPassword && hasFile) {
            throw invalid("Set only one of SPRING_DATASOURCE_PASSWORD and SPRING_DATASOURCE_PASSWORD_FILE");
        }
        if (hasPassword) {
            return password;
        }
        if (!hasFile) {
            throw invalid("SPRING_DATASOURCE_PASSWORD or SPRING_DATASOURCE_PASSWORD_FILE must be set");
        }
        return readSecret(Path.of(passwordFile));
    }

    private static String readSecret(Path file) {
        String content;
        try {
            content = Files.readString(file, StandardCharsets.UTF_8);
        } catch (IOException | RuntimeException e) {
            throw invalid("SPRING_DATASOURCE_PASSWORD_FILE does not point to a readable file");
        }
        String secret = content.replaceAll("[\\r\\n]+$", "");
        if (secret.isEmpty()) {
            throw invalid("SPRING_DATASOURCE_PASSWORD_FILE points to an empty file");
        }
        return secret;
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private static IllegalStateException invalid(String message) {
        return new IllegalStateException(message);
    }

    @Override
    public String toString() {
        return "DatasourceSettings[password=****]";
    }
}
