package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.port.out.PasswordResetStore;
import co.edu.corhuila.synkro.auth.application.port.out.UserRepository;
import co.edu.corhuila.synkro.auth.domain.model.SystemUser;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Honours the contract of the port in memory: a key belongs to the actor that used it, and a reset either changes the
 * hash, revokes the owner and records the audit, or changes nothing. It doubles as the UserRepository so a test sees
 * what the reset saved.
 */
class FakePasswordResetStore implements PasswordResetStore, UserRepository {

    static final String SALES_ID = "11111111-1111-1111-1111-111111111111";
    static final String INVENTORY_ID = "22222222-2222-2222-2222-222222222222";
    static final String OTHER_ADMIN_ID = "33333333-3333-3333-3333-333333333333";
    static final String INACTIVE_ID = "44444444-4444-4444-4444-444444444444";
    static final String MISSING_ID = "99999999-9999-9999-9999-999999999999";

    final Map<String, SystemUser> users = new LinkedHashMap<>();
    /** The records of committed resets, by "actor|key". */
    final Map<String, Recorded> recorded = new LinkedHashMap<>();
    final List<ResetAttribution> audits = new ArrayList<>();
    final List<String> revokedOwners = new ArrayList<>();
    int lookups;
    int resetCalls;

    FakePasswordResetStore() {
        add(Fakes.ADMIN_CALLER.subject(), "ADMIN", true);
        add(OTHER_ADMIN_ID, "ADMIN", true);
        add(SALES_ID, "SALESPERSON", true);
        add(INVENTORY_ID, "INVENTORY", true);
        add(INACTIVE_ID, "SALESPERSON", false);
    }

    final void add(String userId, String role, boolean active) {
        users.put(userId, new SystemUser(userId, "User " + userId.substring(0, 4), userId.substring(0, 4) + "@synkro.test",
            "hashed:" + Fakes.PASSWORD, role, Fakes.NOW, active));
    }

    final void replace(SystemUser user) {
        users.put(user.getUserId(), user);
    }

    static String slot(String actorUserId, String key) {
        return actorUserId + "|" + key;
    }

    @Override
    public Optional<Recorded> findByActorAndKey(String actorUserId, String idempotencyKey) {
        lookups++;
        return Optional.ofNullable(recorded.get(slot(actorUserId, idempotencyKey)));
    }

    @Override
    public Outcome resetPasswordWithAudit(String idempotencyKey, String targetUserId, String newPasswordHash,
                                          ResetAttribution attribution) {
        resetCalls++;
        Recorded existing = recorded.get(slot(attribution.actorUserId(), idempotencyKey));
        if (existing != null) {
            return new Outcome.AlreadyRecorded(existing);
        }
        SystemUser target = users.get(targetUserId);
        if (target == null || !target.isActive() || "ADMIN".equals(target.getRole())) {
            return new Outcome.TargetNotEligible();
        }
        replace(new SystemUser(target.getUserId(), target.getName(), target.getEmail(), newPasswordHash,
            target.getRole(), target.getRegistrationDate(), target.isActive()));
        revokedOwners.add(targetUserId);
        audits.add(attribution);
        recorded.put(slot(attribution.actorUserId(), idempotencyKey), new Recorded(targetUserId, attribution.occurredAt()));
        return new Outcome.Reset(attribution.occurredAt());
    }

    @Override
    public Optional<SystemUser> findByEmail(String email) {
        return users.values().stream().filter(u -> u.getEmail().equals(email)).findFirst();
    }

    @Override
    public Optional<SystemUser> findById(String userId) {
        return Optional.ofNullable(users.get(userId));
    }

    @Override
    public SearchResult search(SearchCriteria criteria) {
        throw new UnsupportedOperationException("Password reset tests do not search users");
    }
}
