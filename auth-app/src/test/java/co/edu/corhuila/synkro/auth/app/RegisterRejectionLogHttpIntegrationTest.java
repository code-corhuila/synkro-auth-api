package co.edu.corhuila.synkro.auth.app;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.slf4j.LoggerFactory;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.security.KeyPair;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Rejected registrations are recorded in the security log, outside the success transaction and never in
 * user_creation_audit. The log carries who asked and why it failed, and nothing that came from the request body.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@EnabledIfEnvironmentVariable(named = DatabaseTestSupport.URL_VARIABLE, matches = ".+")
class RegisterRejectionLogHttpIntegrationTest {

    private static final KeyPair KEYS = TestKeys.generate(2048);
    private static final String PASSWORD = "pw-" + UUID.randomUUID();
    private static final String SECURITY_LOGGER = "synkro.auth.security";

    @DynamicPropertySource
    static void configuration(DynamicPropertyRegistry registry) throws Exception {
        DatabaseTestSupport.registerSigningKey(registry, KEYS, "register-rejection-log-test");
        DatabaseTestSupport.registerDatasource(registry);
    }

    @LocalServerPort
    int port;

    private final TestRestTemplate http = new TestRestTemplate();
    private final JdbcTemplate jdbc = DatabaseTestSupport.jdbc();
    private final ListAppender<ILoggingEvent> everything = new ListAppender<>();
    private Logger root;

    @BeforeEach
    void captureLogs() {
        root = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
        everything.start();
        root.addAppender(everything);
    }

    @AfterEach
    void releaseLogs() {
        root.detachAppender(everything);
    }

    private static Map<String, Object> request(String email, String name) {
        Map<String, Object> body = new HashMap<>();
        body.put("name", name);
        body.put("email", email);
        body.put("password", PASSWORD);
        body.put("role", "SALESPERSON");
        return body;
    }

    private ResponseEntity<String> register(Map<String, Object> body, String token, String correlationId) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("Idempotency-Key", "it-key-" + UUID.randomUUID());
        headers.set("X-Correlation-Id", correlationId);
        if (token != null) {
            headers.setBearerAuth(token);
        }
        return http.exchange("http://localhost:" + port + "/api/v1/auth/register", HttpMethod.POST,
            new HttpEntity<>(body, headers), String.class);
    }

    private static String tokenFor(String subject, String role) {
        return Jwts.builder()
            .subject(subject)
            .claim("roles", List.of(role))
            .claim("permissions", List.of())
            .expiration(Date.from(Instant.now().plusSeconds(300)))
            .signWith(KEYS.getPrivate(), Jwts.SIG.RS256)
            .compact();
    }

    private List<ILoggingEvent> securityEventsOf(String correlationId) {
        return everything.list.stream()
            .filter(e -> e.getLoggerName().equals(SECURITY_LOGGER))
            .filter(e -> e.getFormattedMessage().contains(correlationId))
            .toList();
    }

    private int totalAuditRows() {
        return jdbc.queryForObject("SELECT count(*) FROM auth_schema.user_creation_audit", Integer.class);
    }

    /** Every line any logger wrote, with the text of its exception, as one string to search. */
    private String allLoggedText() {
        StringBuilder text = new StringBuilder();
        for (ILoggingEvent event : List.copyOf(everything.list)) {
            text.append(event.getFormattedMessage()).append('\n');
            if (event.getThrowableProxy() != null) {
                text.append(event.getThrowableProxy().getMessage()).append('\n');
            }
        }
        return text.toString();
    }

    @Test
    @Tag("NFR-005")
    void rejectedAttempts_areInTheSecurityLog_notInTheAuditTable_andLeakNothing() {
        String adminId = DatabaseTestSupport.insertUser(jdbc, DatabaseTestSupport.uniqueEmail(), PASSWORD, "ADMIN", true);
        String adminToken = tokenFor(adminId, "ADMIN");
        String salespersonId = DatabaseTestSupport.insertUser(jdbc, DatabaseTestSupport.uniqueEmail(), PASSWORD, "SALESPERSON", true);
        String salespersonToken = tokenFor(salespersonId, "SALESPERSON");
        String takenEmail = DatabaseTestSupport.uniqueEmail();
        register(request(takenEmail, "First Owner"), adminToken, "corr-seed-" + UUID.randomUUID());

        String secretName = "Secret Name " + UUID.randomUUID();
        String payloadEmail = DatabaseTestSupport.uniqueEmail();
        String ghostAdminId = UUID.randomUUID().toString();
        String ghostToken = tokenFor(ghostAdminId, "ADMIN");
        Map<String, HttpStatus> statuses = new java.util.LinkedHashMap<>();
        int auditBefore = totalAuditRows();

        String noToken = "corr-401-" + UUID.randomUUID();
        statuses.put(noToken, HttpStatus.valueOf(register(request(payloadEmail, secretName), null, noToken).getStatusCode().value()));
        String forbidden = "corr-403-" + UUID.randomUUID();
        statuses.put(forbidden, HttpStatus.valueOf(register(request(payloadEmail, secretName), salespersonToken, forbidden).getStatusCode().value()));
        String duplicate = "corr-422-" + UUID.randomUUID();
        statuses.put(duplicate, HttpStatus.valueOf(register(request(takenEmail, secretName), adminToken, duplicate).getStatusCode().value()));
        String invalid = "corr-400-" + UUID.randomUUID();
        statuses.put(invalid, HttpStatus.valueOf(register(request("not-an-email", secretName), adminToken, invalid).getStatusCode().value()));
        String ghost = "corr-403g-" + UUID.randomUUID();
        statuses.put(ghost, HttpStatus.valueOf(register(request(payloadEmail, secretName), ghostToken, ghost).getStatusCode().value()));

        assertThat(statuses.values()).containsExactly(HttpStatus.UNAUTHORIZED, HttpStatus.FORBIDDEN,
            HttpStatus.UNPROCESSABLE_ENTITY, HttpStatus.BAD_REQUEST, HttpStatus.FORBIDDEN);
        for (String correlationId : statuses.keySet()) {
            List<ILoggingEvent> events = securityEventsOf(correlationId);
            assertThat(events).as("security log for " + correlationId).hasSize(1);
        }
        assertThat(securityEventsOf(noToken).get(0).getFormattedMessage()).contains("status=401");
        assertThat(securityEventsOf(forbidden).get(0).getFormattedMessage()).contains("reason=FORBIDDEN");
        assertThat(securityEventsOf(duplicate).get(0).getFormattedMessage()).contains("reason=BUSINESS_RULE");
        assertThat(securityEventsOf(invalid).get(0).getFormattedMessage()).contains("reason=INVALID_REQUEST");
        assertThat(securityEventsOf(ghost).get(0).getFormattedMessage()).contains("reason=FORBIDDEN");

        // nothing was added to the audit table by any of them, and no user exists for the payload email
        assertThat(totalAuditRows()).isEqualTo(auditBefore);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM auth_schema.system_user WHERE email = ?", Integer.class, payloadEmail)).isZero();

        // the only identifiers a rejection may carry are the callers own: no user was created, so none is invented
        java.util.regex.Pattern uuid = java.util.regex.Pattern.compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
        for (String correlationId : statuses.keySet()) {
            java.util.regex.Matcher found = uuid.matcher(securityEventsOf(correlationId).get(0).getFormattedMessage().replace(correlationId, ""));
            while (found.find()) {
                assertThat(found.group()).isIn(adminId, ghostAdminId, salespersonId);
            }
        }

        String logged = allLoggedText();
        assertThat(logged).doesNotContain(PASSWORD).doesNotContain(secretName).doesNotContain(payloadEmail)
            .doesNotContain(adminToken).doesNotContain(salespersonToken).doesNotContain(ghostToken)
            .doesNotContain("$2a$").doesNotContain("$2b$").doesNotContain("password_hash").doesNotContain("passwordHash");
    }
}
