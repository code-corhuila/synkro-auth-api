package co.edu.corhuila.synkro.auth.domain.model;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

/** What is known about an issued service token. The signed token itself is never part of it (ADR-006). */
public record ServiceToken(String tokenId, String service, List<String> permissions, String issuedBy,
                           Instant issuedAt, Instant expiresAt) {

    public static final Duration LIFETIME = Duration.ofDays(30);

    public ServiceToken {
        permissions = List.copyOf(permissions);
    }

    public static ServiceToken issue(ServiceAccount account, String tokenId, String issuedBy, Instant issuedAt) {
        return new ServiceToken(tokenId, account.serviceName(), account.permissions(), issuedBy,
            issuedAt, issuedAt.plus(LIFETIME));
    }
}
