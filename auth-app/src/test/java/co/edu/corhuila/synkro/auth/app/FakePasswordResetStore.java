package co.edu.corhuila.synkro.auth.app;

import co.edu.corhuila.synkro.auth.application.port.out.PasswordResetStore;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * For the HTTP tests that need no database: it remembers what the use case handed over and reports a committed reset.
 * What the unit does to rows is checked against PostgreSQL by JdbcPasswordResetStoreIntegrationTest.
 */
class FakePasswordResetStore implements PasswordResetStore {

    record Call(String idempotencyKey, String targetUserId, String newPasswordHash, ResetAttribution attribution) {}

    final List<Call> calls = new CopyOnWriteArrayList<>();

    @Override
    public Optional<Recorded> findByActorAndKey(String actorUserId, String idempotencyKey) {
        return Optional.empty();
    }

    @Override
    public Outcome resetPasswordWithAudit(String idempotencyKey, String targetUserId, String newPasswordHash,
                                          ResetAttribution attribution) {
        calls.add(new Call(idempotencyKey, targetUserId, newPasswordHash, attribution));
        return new Outcome.Reset(attribution.occurredAt());
    }
}
