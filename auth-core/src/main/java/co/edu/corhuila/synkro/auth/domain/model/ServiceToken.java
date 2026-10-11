package co.edu.corhuila.synkro.auth.domain.model;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

public record ServiceToken(String tokenId, String service, List<String> permissions, String issuedBy,
                           Instant issuedAt, Instant expiresAt) {

    public static final Duration LIFETIME = Duration.ofDays(30);

    public static ServiceToken issue(ServiceAccount account, String tokenId, String issuedBy, Instant issuedAt) {
        throw new UnsupportedOperationException("not implemented");
    }
}
