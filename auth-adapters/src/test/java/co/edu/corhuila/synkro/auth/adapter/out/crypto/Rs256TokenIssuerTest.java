package co.edu.corhuila.synkro.auth.adapter.out.crypto;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Duration;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Proves the signer by verifying what it produces with the matching public key,
 * not by reading the signing code: a token that merely "didn't throw" would also
 * pass a signing-only test with the wrong key.
 */
class Rs256TokenIssuerTest {

    private static final Duration TTL = Duration.ofMinutes(15);

    private static KeyPair generate(int bits) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(bits);
        return generator.generateKeyPair();
    }

    @Test
    void tokenSignedWithThePrivateKey_verifiesWithThePublicKey_andCarriesTheExpectedClaims() throws Exception {
        KeyPair pair = generate(2048);
        String token = new Rs256TokenIssuer(pair.getPrivate(), TTL).issueAccessToken("user-42", "SALESPERSON");

        Jws<Claims> jws = Jwts.parser().verifyWith(pair.getPublic()).build().parseSignedClaims(token);
        Claims claims = jws.getPayload();

        assertThat(claims.getSubject()).isEqualTo("user-42");
        assertThat(claims.get("roles", List.class)).containsExactly("SALESPERSON");
        assertThat(claims.getId()).isNotBlank();
        assertThat(claims.getIssuedAt()).isNotNull();
        assertThat(claims.getExpiration().getTime() - claims.getIssuedAt().getTime())
            .isEqualTo(TTL.toMillis());
    }

    @Test
    void tokenCarriesTheRolesPermissions_asRequiredByTheTokenContract() throws Exception {
        KeyPair pair = generate(2048);
        String token = new Rs256TokenIssuer(pair.getPrivate(), TTL).issueAccessToken("u", "INVENTORY");

        Claims claims = Jwts.parser().verifyWith(pair.getPublic()).build().parseSignedClaims(token).getPayload();

        assertThat(claims.get("permissions", List.class)).containsExactlyInAnyOrder("products:read", "products:write");
    }

    @Test
    void headerDeclaresRs256() throws Exception {
        KeyPair pair = generate(2048);
        String token = new Rs256TokenIssuer(pair.getPrivate(), TTL).issueAccessToken("u", "ADMIN");

        Jws<Claims> jws = Jwts.parser().verifyWith(pair.getPublic()).build().parseSignedClaims(token);

        assertThat(jws.getHeader().getAlgorithm()).isEqualTo("RS256");
    }

    @Test
    void headerStaysRs256_evenForALargerKey() throws Exception {
        // jjwt infers the algorithm from key size when none is named (3072 -> RS384),
        // which would silently break every consumer expecting RS256.
        KeyPair pair = generate(3072);
        String token = new Rs256TokenIssuer(pair.getPrivate(), TTL).issueAccessToken("u", "ADMIN");

        assertThat(Jwts.parser().verifyWith(pair.getPublic()).build().parseSignedClaims(token)
            .getHeader().getAlgorithm()).isEqualTo("RS256");
    }

    @Test
    void signatureIsAlsoValidUnderPlainJcaSha256WithRsa_independentOfThejwtLibrary() throws Exception {
        KeyPair pair = generate(2048);
        String token = new Rs256TokenIssuer(pair.getPrivate(), TTL).issueAccessToken("u", "ADMIN");
        String[] parts = token.split("\\.");

        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(pair.getPublic());
        verifier.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));

        assertThat(verifier.verify(Base64.getUrlDecoder().decode(parts[2]))).isTrue();
    }

    @Test
    void tokenIsRejectedByADifferentPublicKey() throws Exception {
        KeyPair signer = generate(2048);
        KeyPair stranger = generate(2048);
        String token = new Rs256TokenIssuer(signer.getPrivate(), TTL).issueAccessToken("u", "ADMIN");

        assertThatThrownBy(() -> Jwts.parser().verifyWith(stranger.getPublic()).build().parseSignedClaims(token))
            .isInstanceOf(JwtException.class);
    }

    @Test
    void tamperedPayloadIsRejected() throws Exception {
        KeyPair pair = generate(2048);
        Rs256TokenIssuer issuer = new Rs256TokenIssuer(pair.getPrivate(), TTL);
        String[] genuine = issuer.issueAccessToken("u", "INVENTORY").split("\\.");
        String[] other = issuer.issueAccessToken("u", "ADMIN").split("\\.");
        String forged = genuine[0] + "." + other[1] + "." + genuine[2];

        assertThatThrownBy(() -> Jwts.parser().verifyWith(pair.getPublic()).build().parseSignedClaims(forged))
            .isInstanceOf(JwtException.class);
    }

    @Test
    void expiredTokenIsRejected() throws Exception {
        KeyPair pair = generate(2048);
        String token = new Rs256TokenIssuer(pair.getPrivate(), Duration.ofSeconds(-60)).issueAccessToken("u", "ADMIN");

        assertThatThrownBy(() -> Jwts.parser().verifyWith(pair.getPublic()).build().parseSignedClaims(token))
            .isInstanceOf(ExpiredJwtException.class);
    }

    @Test
    void everyAccessTokenGetsItsOwnJti() throws Exception {
        KeyPair pair = generate(2048);
        Rs256TokenIssuer issuer = new Rs256TokenIssuer(pair.getPrivate(), TTL);

        String a = Jwts.parser().verifyWith(pair.getPublic()).build()
            .parseSignedClaims(issuer.issueAccessToken("u", "ADMIN")).getPayload().getId();
        String b = Jwts.parser().verifyWith(pair.getPublic()).build()
            .parseSignedClaims(issuer.issueAccessToken("u", "ADMIN")).getPayload().getId();

        assertThat(a).isNotEqualTo(b);
    }

    @Test
    void refreshToken_isOpaqueUniqueAndLongEnough() throws Exception {
        Rs256TokenIssuer issuer = new Rs256TokenIssuer(generate(2048).getPrivate(), TTL);

        Set<String> seen = new HashSet<>();
        for (int i = 0; i < 100; i++) {
            String token = issuer.issueRefreshToken();
            assertThat(token).hasSizeGreaterThanOrEqualTo(43); // 256 bits, base64url
            assertThat(token).doesNotContain("."); // not a JWT
            assertThat(seen.add(token)).isTrue();
        }
    }
}
