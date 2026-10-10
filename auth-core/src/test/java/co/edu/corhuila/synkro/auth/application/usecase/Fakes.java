package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.port.out.HashFunction;
import co.edu.corhuila.synkro.auth.application.port.out.PasswordHasher;
import co.edu.corhuila.synkro.auth.application.port.out.RefreshTokenStore;
import co.edu.corhuila.synkro.auth.application.port.out.TokenIssuer;
import co.edu.corhuila.synkro.auth.application.port.out.UserRepository;
import co.edu.corhuila.synkro.auth.domain.model.SystemUser;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

/** Hand-written test doubles: auth-core has no mocking library and needs none. */
final class Fakes {
    private Fakes() {}

    static final String PASSWORD = "correct-password";

    static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");
    static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    static final Duration REFRESH_TTL = Duration.ofDays(7);

    /** Fake "hash" is a prefix, so a test can tell a hash from the plaintext. */
    static final PasswordHasher PASSWORD_HASHER = new PasswordHasher() {
        @Override
        public String hash(String plaintext) {
            return "hashed:" + plaintext;
        }

        @Override
        public boolean matches(String plaintext, String hash) {
            return hash.equals("hashed:" + plaintext);
        }
    };

    /** Prefixing keeps the stored value distinguishable from the raw token. */
    static final HashFunction HASH = value -> "sha:" + value;

    static SystemUser user(String email, boolean active) {
        return new SystemUser("u-1", "Ana", email, "hashed:" + PASSWORD, "ADMIN", NOW, active);
    }

    static UserRepository users(SystemUser... users) {
        Map<String, SystemUser> byEmail = new HashMap<>();
        Map<String, SystemUser> byId = new HashMap<>();
        for (SystemUser u : users) {
            byEmail.put(u.getEmail(), u);
            byId.put(u.getUserId(), u);
        }
        return new UserRepository() {
            @Override
            public Optional<SystemUser> findByEmail(String email) {
                return Optional.ofNullable(byEmail.get(email));
            }

            @Override
            public Optional<SystemUser> findById(String userId) {
                return Optional.ofNullable(byId.get(userId));
            }
        };
    }

    static class RecordingTokenIssuer implements TokenIssuer {
        final List<String> accessSubjects = new ArrayList<>();
        final List<String> accessRoles = new ArrayList<>();
        private final AtomicInteger refreshCounter = new AtomicInteger();

        @Override
        public String issueAccessToken(String subject, String role) {
            accessSubjects.add(subject);
            accessRoles.add(role);
            return "access-" + subject + "-" + role + "-" + accessSubjects.size();
        }

        @Override
        public String issueRefreshToken() {
            return "refresh-" + refreshCounter.incrementAndGet();
        }
    }

    /** Same one-time-use contract as the real port: consuming removes the entry. */
    static class FakeRefreshTokenStore implements RefreshTokenStore {
        final Map<String, String> hashToUser = new HashMap<>();
        final Map<String, Instant> hashToExpiry = new HashMap<>();

        @Override
        public void save(String tokenHash, String userId, Instant expiresAt) {
            hashToUser.put(tokenHash, userId);
            hashToExpiry.put(tokenHash, expiresAt);
        }

        @Override
        public Optional<String> consumeAndRotate(String tokenHash) {
            return Optional.ofNullable(hashToUser.remove(tokenHash));
        }
    }
}
