package co.edu.corhuila.synkro.auth.adapter.out.crypto;

import co.edu.corhuila.synkro.auth.application.usecase.InvalidTokenException;
import co.edu.corhuila.synkro.auth.domain.model.AuthenticatedCaller;
import co.edu.corhuila.synkro.auth.domain.model.Roles;
import co.edu.corhuila.synkro.auth.domain.model.ServiceAccount;
import co.edu.corhuila.synkro.auth.domain.model.ServiceToken;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** The token is checked by parsing it with the public key, never by reading the signing code. */
class Rs256ServiceTokenSignerTest {

    private static final Instant ISSUED_AT = Instant.parse("2026-03-01T10:15:30Z");
    private static final String TOKEN_ID = "6f1f4a3e-2b7d-4c1a-9a55-0d6f3d9c1e10";
    private static final String ADMIN_ID = "0b9c7e0a-52d1-4f55-8f7e-3a1d2c4b5e66";

    private static KeyPair pair;
    private static KeyPair otherPair;
    private static ServiceToken workflowToken;
    private static String signed;

    @BeforeAll
    static void keys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        pair = generator.generateKeyPair();
        otherPair = generator.generateKeyPair();
        workflowToken = ServiceToken.issue(ServiceAccount.WORKFLOW, TOKEN_ID, ADMIN_ID, ISSUED_AT);
        signed = new Rs256ServiceTokenSigner(pair.getPrivate()).sign(workflowToken);
    }

    private static Jws<Claims> parse(String token) {
        return Jwts.parser().verifyWith(pair.getPublic())
            .clock(() -> Date.from(ISSUED_AT.plusSeconds(60)))
            .build().parseSignedClaims(token);
    }

    private static Rs256TokenVerifier verifierAt(Instant now) {
        return new Rs256TokenVerifier(pair.getPublic(), Clock.fixed(now, ZoneOffset.UTC));
    }

    @Test
    void theTokenIsSignedWithRs256() {
        assertThat(parse(signed).getHeader().getAlgorithm()).isEqualTo("RS256");
    }

    @Test
    void theClaimsAreTheOnesOfAdr006() {
        Claims claims = parse(signed).getPayload();

        assertThat(claims.getSubject()).isEqualTo("synkro-workflow");
        assertThat(claims.get("roles", List.class)).containsExactly("SERVICE");
        assertThat(claims.get("permissions", List.class))
            .containsExactlyInAnyOrder("customers:read", "stock:reserve", "stock:release", "sales:register");
        assertThat(claims.getId()).isEqualTo(TOKEN_ID);
        assertThat(claims.getIssuedAt().toInstant()).isEqualTo(ISSUED_AT);
        assertThat(claims.getExpiration().toInstant()).isEqualTo(ISSUED_AT.plus(Duration.ofDays(30)));
    }

    @Test
    void theTokenCarriesNothingElse() {
        assertThat(parse(signed).getPayload().keySet())
            .containsExactlyInAnyOrder("sub", "roles", "permissions", "jti", "iat", "exp");
    }

    @Test
    void theWorkerTokenCarriesTheWorkerPermissions() {
        ServiceToken worker = ServiceToken.issue(ServiceAccount.WORKER, TOKEN_ID, ADMIN_ID, ISSUED_AT);

        Claims claims = parse(new Rs256ServiceTokenSigner(pair.getPrivate()).sign(worker)).getPayload();

        assertThat(claims.getSubject()).isEqualTo("synkro-worker");
        assertThat(claims.get("permissions", List.class))
            .containsExactlyInAnyOrder("products:read", "stock-alerts:read", "stock-alerts:write");
    }

    @Test
    void theVerifierOfThisServiceAcceptsItAsAServiceCallerWithExactlyThosePermissions() {
        AuthenticatedCaller caller = verifierAt(ISSUED_AT.plusSeconds(60)).verify(signed);

        assertThat(caller.subject()).isEqualTo("synkro-workflow");
        assertThat(caller.roles()).isEqualTo(Set.of(Roles.SERVICE));
        assertThat(caller.isService()).isTrue();
        assertThat(caller.permissions())
            .isEqualTo(Set.of("customers:read", "stock:reserve", "stock:release", "sales:register"));
    }

    @Test
    void aTokenSignedWithAnotherKeyIsRejected() {
        String foreign = new Rs256ServiceTokenSigner(otherPair.getPrivate()).sign(workflowToken);

        assertThatThrownBy(() -> verifierAt(ISSUED_AT.plusSeconds(60)).verify(foreign))
            .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void theTokenIsAcceptedUntilItsExpiryAndSkewAndRejectedAfter() {
        Instant expiry = workflowToken.expiresAt();

        assertThat(verifierAt(expiry.minusSeconds(1)).verify(signed).isService()).isTrue();
        assertThat(verifierAt(expiry.plusSeconds(29)).verify(signed).isService()).isTrue();
        assertThatThrownBy(() -> verifierAt(expiry.plusSeconds(31)).verify(signed))
            .isInstanceOf(InvalidTokenException.class);
    }
}
