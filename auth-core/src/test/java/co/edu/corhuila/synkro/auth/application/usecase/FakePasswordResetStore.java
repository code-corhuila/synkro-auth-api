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
    /** The permanent reservations of committed resets, by "actor|key": they never expire and are never removed. */
    final Map<String, Recorded> recorded = new LinkedHashMap<>();
    /** The private receipts, by "actor|key": the bcrypt string that was assigned. Expiry or cleanup removes one. */
    final Map<String, String> receipts = new LinkedHashMap<>();
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

    /** The receipt window ended, or the cleanup removed the row: the key stays recorded and consumed. */
    final void expireReceipt(String actorUserId, String idempotencyKey) {
        receipts.remove(slot(actorUserId, idempotencyKey));
    }

    private Optional<Recorded> view(String slot) {
        Recorded base = recorded.get(slot);
        if (base == null) {
            return Optional.empty();
        }
        return Optional.of(new Recorded(base.targetUserId(), base.occurredAt(),
            Optional.ofNullable(receipts.get(slot)).map(RequestReceipt::new)));
    }

    @Override
    public Optional<Recorded> findByActorAndKey(String actorUserId, String idempotencyKey) {
        lookups++;
        return view(slot(actorUserId, idempotencyKey));
    }

    @Override
    public Outcome resetPasswordWithAudit(String idempotencyKey, String targetUserId, String newPasswordHash,
                                          ResetAttribution attribution) {
        resetCalls++;
        Optional<Recorded> existing = view(slot(attribution.actorUserId(), idempotencyKey));
        if (existing.isPresent()) {
            return new Outcome.AlreadyRecorded(existing.get());
        }
        SystemUser target = users.get(targetUserId);
        if (target == null || !target.isActive() || "ADMIN".equals(target.getRole())) {
            return new Outcome.TargetNotEligible();
        }
        replace(new SystemUser(target.getUserId(), target.getName(), target.getEmail(), newPasswordHash,
            target.getRole(), target.getRegistrationDate(), target.isActive()));
        revokedOwners.add(targetUserId);
        audits.add(attribution);
        String slot = slot(attribution.actorUserId(), idempotencyKey);
        recorded.put(slot, new Recorded(targetUserId, attribution.occurredAt(), Optional.empty()));
        // The same string that was assigned to the user, never a second hash.
        receipts.put(slot, newPasswordHash);
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
