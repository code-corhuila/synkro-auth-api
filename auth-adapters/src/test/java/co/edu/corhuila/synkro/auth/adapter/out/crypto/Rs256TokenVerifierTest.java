package co.edu.corhuila.synkro.auth.adapter.out.crypto;

import co.edu.corhuila.synkro.auth.application.usecase.InvalidTokenException;
import co.edu.corhuila.synkro.auth.domain.model.AuthenticatedCaller;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tokens are built here with explicit timestamps and verified against a fixed clock, so
 * no test sleeps. The RS384 and PS256 tokens are signed with the very key the verifier
 * trusts, so only the explicit RS256-only rule can reject them.
 */
class Rs256TokenVerifierTest {

    private static final Instant NOW = Instant.parse("2026-01-15T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

    private static KeyPair pair;
    private static KeyPair otherPair;
    private static Rs256TokenVerifier verifier;

    @BeforeAll
    static void keys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        pair = generator.generateKeyPair();
        otherPair = generator.generateKeyPair();
        verifier = new Rs256TokenVerifier(pair.getPublic(), CLOCK);
    }

    private static JwtBuilder claims(Instant expiresAt) {
        return Jwts.builder()
            .subject("user-42")
            .claim("roles", List.of("SALESPERSON"))
            .claim("permissions", List.of("sales:create", "sales:read"))
            .expiration(Date.from(expiresAt));
    }

    private static String signed(Instant expiresAt) {
        return claims(expiresAt).signWith(pair.getPrivate(), Jwts.SIG.RS256).compact();
    }

    private static void assertRejected(String token) {
        assertThatThrownBy(() -> verifier.verify(token)).isInstanceOf(InvalidTokenException.class);
    }

    // ── accepted ─────────────────────────────────────────────────────

    @Test
    void aTokenIssuedByTheIssuerWithTheMatchingKey_isAccepted_andYieldsSubjectRolesAndPermissions() {
        String token = new Rs256TokenIssuer(pair.getPrivate(), Duration.ofMinutes(5)).issueAccessToken("user-7", "INVENTORY");

        AuthenticatedCaller caller = new Rs256TokenVerifier(pair.getPublic(), Clock.systemUTC()).verify(token);

        assertThat(caller.subject()).isEqualTo("user-7");
        assertThat(caller.roles()).containsExactly("INVENTORY");
        assertThat(caller.permissions()).containsExactlyInAnyOrder("products:read", "products:write");
    }

    @Test
    void aTokenWithoutRolesOrPermissionsClaims_isAcceptedAsACallerWithNone() {
        String token = Jwts.builder().subject("svc").expiration(Date.from(NOW.plusSeconds(60)))
            .signWith(pair.getPrivate(), Jwts.SIG.RS256).compact();

        AuthenticatedCaller caller = verifier.verify(token);

        assertThat(caller.roles()).isEmpty();
        assertThat(caller.permissions()).isEmpty();
    }

    // ── expiry and clock skew ────────────────────────────────────────

    @Test
    void aTokenExpiredBy20Seconds_isAccepted() {
        assertThat(verifier.verify(signed(NOW.minusSeconds(20))).subject()).isEqualTo("user-42");
    }

    @Test
    void aTokenExpiredBy30Seconds_isStillAccepted() {
        assertThat(verifier.verify(signed(NOW.minusSeconds(30))).subject()).isEqualTo("user-42");
    }

    @Test
    void aTokenExpiredBy31Seconds_isRejected() {
        assertRejected(signed(NOW.minusSeconds(31)));
    }

    @Test
    void aTokenExpiredAnHourAgo_isRejected() {
        assertRejected(signed(NOW.minus(Duration.ofHours(1))));
    }

    // ── signature ────────────────────────────────────────────────────

    @Test
    void aTokenSignedWithAnotherRsaKey_isRejected() {
        assertRejected(claims(NOW.plusSeconds(60)).signWith(otherPair.getPrivate(), Jwts.SIG.RS256).compact());
    }

    @Test
    void aTokenWithATamperedPayload_isRejected() {
        String[] parts = signed(NOW.plusSeconds(60)).split("\\.");
        String forgedPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(
            ("{\"sub\":\"attacker\",\"roles\":[\"ADMIN\"],\"exp\":" + NOW.plusSeconds(60).getEpochSecond() + "}")
                .getBytes(StandardCharsets.UTF_8));

        assertRejected(parts[0] + "." + forgedPayload + "." + parts[2]);
    }

    // ── algorithm ────────────────────────────────────────────────────

    @Test
    void algNone_isRejected() {
        assertRejected(claims(NOW.plusSeconds(60)).compact());
    }

    @Test
    void algNoneBuiltByHandWithAnEmptySignatureSegment_isRejected() {
        String header = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"alg\":\"none\"}".getBytes(StandardCharsets.UTF_8));
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(
            ("{\"sub\":\"x\",\"exp\":" + NOW.plusSeconds(60).getEpochSecond() + "}").getBytes(StandardCharsets.UTF_8));

        assertRejected(header + "." + payload + ".");
    }

    @Test
    void hs256SignedWithThePublicKeyBytes_algorithmConfusion_isRejected() {
        var secret = Keys.hmacShaKeyFor(pair.getPublic().getEncoded());

        assertRejected(claims(NOW.plusSeconds(60)).signWith(secret, Jwts.SIG.HS256).compact());
    }

    @Test
    void rs384WithAValidSignatureFromTheRightKey_isRejectedBecauseOnlyRs256IsAccepted() {
        assertRejected(claims(NOW.plusSeconds(60)).signWith(pair.getPrivate(), Jwts.SIG.RS384).compact());
    }

    @Test
    void ps256WithAValidSignatureFromTheRightKey_isRejectedBecauseOnlyRs256IsAccepted() {
        assertRejected(claims(NOW.plusSeconds(60)).signWith(pair.getPrivate(), Jwts.SIG.PS256).compact());
    }

    // ── required claims and shapes ───────────────────────────────────

    @Test
    void aTokenWithoutSub_isRejected() {
        assertRejected(Jwts.builder().expiration(Date.from(NOW.plusSeconds(60)))
            .signWith(pair.getPrivate(), Jwts.SIG.RS256).compact());
    }

    @Test
    void aTokenWithoutExp_isRejected() {
        assertRejected(Jwts.builder().subject("user-42").signWith(pair.getPrivate(), Jwts.SIG.RS256).compact());
    }

    @Test
    void aTokenWhoseRolesClaimIsNotAList_isRejected() {
        assertRejected(Jwts.builder().subject("user-42").claim("roles", "ADMIN").expiration(Date.from(NOW.plusSeconds(60)))
            .signWith(pair.getPrivate(), Jwts.SIG.RS256).compact());
    }

    @Test
    void emptyBlankNullAndGarbage_areRejected() {
        assertRejected("");
        assertRejected("   ");
        assertRejected(null);
        assertRejected("not-a-token");
        assertRejected("a.b.c");
        assertRejected("....");
    }
}
