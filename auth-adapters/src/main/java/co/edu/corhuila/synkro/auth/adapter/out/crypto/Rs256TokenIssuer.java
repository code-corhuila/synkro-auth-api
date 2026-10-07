package co.edu.corhuila.synkro.auth.adapter.out.crypto;

import co.edu.corhuila.synkro.auth.application.port.out.TokenIssuer;
import co.edu.corhuila.synkro.auth.domain.model.RolePermissions;
import io.jsonwebtoken.Jwts;

import java.security.PrivateKey;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.UUID;

public class Rs256TokenIssuer implements TokenIssuer {
    private static final int REFRESH_TOKEN_BYTES = 32;

    private final PrivateKey privateKey;
    private final Duration accessTokenTtl;
    private final SecureRandom secureRandom = new SecureRandom();

    public Rs256TokenIssuer(PrivateKey privateKey, Duration accessTokenTtl) {
        this.privateKey = privateKey;
        this.accessTokenTtl = accessTokenTtl;
    }

    @Override
    public String issueAccessToken(String subject, String role) {
        Instant now = Instant.now();
        return Jwts.builder()
            .subject(subject)
            .claim("roles", List.of(role))
            .claim("permissions", RolePermissions.forRole(role))
            .id(UUID.randomUUID().toString())
            .issuedAt(Date.from(now))
            .expiration(Date.from(now.plus(accessTokenTtl)))
            // The algorithm is named explicitly: with signWith(key) alone, jjwt infers it from
            // the key size, so a 3072-bit key would silently produce RS384 tokens.
            .signWith(privateKey, Jwts.SIG.RS256)
            .compact();
    }

    @Override
    public String issueRefreshToken() {
        byte[] bytes = new byte[REFRESH_TOKEN_BYTES];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
