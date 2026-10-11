package co.edu.corhuila.synkro.auth.app;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import co.edu.corhuila.synkro.auth.application.port.out.UserRegistrationStore;
import co.edu.corhuila.synkro.auth.domain.model.SystemUser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
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
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A genuine failure of the audit write, over real HTTP and real PostgreSQL. The administrator in the token exists, so the
 * request is authorized; a test-only decorator then names a creator that does not exist in the attribution it hands the
 * real store, so the audit row's foreign key fails inside the store's transaction. This is a failure, not a refusal: the
 * answer is 500 INTERNAL_ERROR and the user and the key written just before it are rolled back.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import(RegisterAuditFailureHttpIntegrationTest.CorruptAuditCreator.class)
@EnabledIfEnvironmentVariable(named = DatabaseTestSupport.URL_VARIABLE, matches = ".+")
class RegisterAuditFailureHttpIntegrationTest {

    private static final KeyPair KEYS = TestKeys.generate(2048);
    private static final String PASSWORD = "pw-" + UUID.randomUUID();

    @TestConfiguration
    static class CorruptAuditCreator {
        @Bean
        static BeanPostProcessor corruptTheAuditCreator() {
            return new BeanPostProcessor() {
                @Override
                public Object postProcessAfterInitialization(Object bean, String beanName) {
                    if (!(bean instanceof UserRegistrationStore real)) {
                        return bean;
                    }
                    return new UserRegistrationStore() {
                        @Override
                        public Optional<SystemUser> findByIdempotencyKey(String idempotencyKey) {
                            return real.findByIdempotencyKey(idempotencyKey);
                        }

                        @Override
                        public Registered registerUserWithAttribution(String key, SystemUser user, CreationAttribution a) {
                            return real.registerUserWithAttribution(key, user, new CreationAttribution(
                                a.auditId(), UUID.randomUUID().toString(), a.occurredAt(), a.correlationId()));
                        }
                    };
                }
            };
        }
    }

    @DynamicPropertySource
    static void configuration(DynamicPropertyRegistry registry) throws Exception {
        DatabaseTestSupport.registerSigningKey(registry, KEYS, "register-audit-failure-test");
        DatabaseTestSupport.registerDatasource(registry);
    }

    @LocalServerPort
    int port;

    private final TestRestTemplate http = new TestRestTemplate();
    private final ObjectMapper json = new ObjectMapper();
    private final JdbcTemplate jdbc = DatabaseTestSupport.jdbc();
    private final ListAppender<ILoggingEvent> logged = new ListAppender<>();

    @BeforeEach
    void capture() {
        logged.start();
        ((Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME)).addAppender(logged);
    }

    @AfterEach
    void release() {
        ((Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME)).detachAppender(logged);
    }

    private int count(String table) {
        return jdbc.queryForObject("SELECT count(*) FROM auth_schema." + table, Integer.class);
    }

    @Test
    @Tag("AUTH-REG-04")
    void aFailingAuditWrite_is500InTheCommonEnvelope_andTheUserAndTheKeyAreRolledBackToo() throws Exception {
        String adminId = DatabaseTestSupport.insertUser(jdbc, DatabaseTestSupport.uniqueEmail(), PASSWORD, "ADMIN", true);
        String token = Jwts.builder().subject(adminId).claim("roles", List.of("ADMIN")).claim("permissions", List.of())
            .expiration(Date.from(Instant.now().plusSeconds(300))).signWith(KEYS.getPrivate(), Jwts.SIG.RS256).compact();
        String email = DatabaseTestSupport.uniqueEmail();
        String key = "it-key-" + UUID.randomUUID();
        String correlation = "corr-audit-fail-" + UUID.randomUUID();
        int users = count("system_user");
        int keys = count("idempotency_key");
        int audits = count("user_creation_audit");
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(token);
        headers.set("Idempotency-Key", key);
        headers.set("X-Correlation-Id", correlation);

        ResponseEntity<String> response = http.exchange("http://localhost:" + port + "/api/v1/auth/register", HttpMethod.POST,
            new HttpEntity<>(Map.of("name", "Ana Perez", "email", email, "password", PASSWORD, "role", "INVENTORY"), headers), String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        JsonNode error = json.readTree(response.getBody());
        assertThat(error.get("error").asText()).isEqualTo("INTERNAL_ERROR");
        assertThat(error.get("traceId").asText()).isEqualTo(correlation);
        assertThat(response.getBody()).doesNotContain(email).doesNotContain("user_creation_audit").doesNotContain("constraint");
        assertThat(count("system_user")).isEqualTo(users);
        assertThat(count("idempotency_key")).isEqualTo(keys);
        assertThat(count("user_creation_audit")).isEqualTo(audits);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM auth_schema.system_user WHERE email = ?", Integer.class, email)).isZero();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM auth_schema.idempotency_key WHERE key = ?", Integer.class, key)).isZero();
        assertThat(logged.list).filteredOn(e -> e.getLoggerName().equals(SecurityLog.LOGGER_NAME))
            .filteredOn(e -> e.getFormattedMessage().contains(correlation))
            .singleElement().satisfies(e -> assertThat(e.getFormattedMessage()).contains("reason=FAILED"));
    }
}
