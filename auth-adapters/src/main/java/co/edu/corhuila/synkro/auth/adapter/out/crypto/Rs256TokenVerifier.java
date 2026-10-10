package co.edu.corhuila.synkro.auth.adapter.out.crypto;

import co.edu.corhuila.synkro.auth.application.port.out.AccessTokenVerifier;
import co.edu.corhuila.synkro.auth.application.usecase.InvalidTokenException;
import co.edu.corhuila.synkro.auth.domain.model.AuthenticatedCaller;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;

import java.security.PublicKey;
import java.time.Clock;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Same rules in every service of the system: 07-api/authentication.md, "Validation rules". */
public class Rs256TokenVerifier implements AccessTokenVerifier {
    private static final long CLOCK_SKEW_SECONDS = 30;

    private final JwtParser parser;

    public Rs256TokenVerifier(PublicKey publicKey, Clock clock) {
        this.parser = Jwts.parser()
            .verifyWith(publicKey)
            // jjwt accepts every RSA, PSS, HMAC and EC algorithm by default; the allowed set is
            // emptied and RS256 re-added so nothing else is accepted whatever the token header says.
            // An unsecured (alg none) token is rejected by parseSignedClaims.
            .sig().clear().add(Jwts.SIG.RS256).and()
            .clock(() -> Date.from(clock.instant()))
            .clockSkewSeconds(CLOCK_SKEW_SECONDS)
            .build();
    }

    @Override
    public AuthenticatedCaller verify(String token) {
        try {
            Claims claims = parser.parseSignedClaims(token).getPayload();
            if (claims.getSubject() == null || claims.getSubject().isBlank() || claims.getExpiration() == null) {
                throw new InvalidTokenException();
            }
            return new AuthenticatedCaller(claims.getSubject(), stringSet(claims, "roles"), stringSet(claims, "permissions"));
        } catch (JwtException | IllegalArgumentException e) {
            throw new InvalidTokenException(e);
        }
    }

    private static Set<String> stringSet(Claims claims, String name) {
        Object value = claims.get(name);
        if (value == null) {
            return Set.of();
        }
        if (!(value instanceof List<?> items)) {
            throw new InvalidTokenException();
        }
        Set<String> strings = new HashSet<>();
        for (Object item : items) {
            if (!(item instanceof String text)) {
                throw new InvalidTokenException();
            }
            strings.add(text);
        }
        return strings;
    }
}
