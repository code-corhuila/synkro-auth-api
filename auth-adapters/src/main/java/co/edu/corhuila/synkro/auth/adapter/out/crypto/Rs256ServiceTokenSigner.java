package co.edu.corhuila.synkro.auth.adapter.out.crypto;

import co.edu.corhuila.synkro.auth.application.port.out.ServiceTokenSigner;
import co.edu.corhuila.synkro.auth.domain.model.Roles;
import co.edu.corhuila.synkro.auth.domain.model.ServiceToken;
import io.jsonwebtoken.Jwts;

import java.security.PrivateKey;
import java.util.Date;
import java.util.List;

public class Rs256ServiceTokenSigner implements ServiceTokenSigner {
    private final PrivateKey privateKey;

    public Rs256ServiceTokenSigner(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    @Override
    public String sign(ServiceToken token) {
        return Jwts.builder()
            .subject(token.service())
            .claim("roles", List.of(Roles.SERVICE))
            .claim("permissions", token.permissions())
            .id(token.tokenId())
            .issuedAt(Date.from(token.issuedAt()))
            .expiration(Date.from(token.expiresAt()))
            // Named explicitly: with signWith(key) alone, jjwt picks the algorithm from the key size.
            .signWith(privateKey, Jwts.SIG.RS256)
            .compact();
    }
}
