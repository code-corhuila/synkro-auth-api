package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.port.out.IdGenerator;
import co.edu.corhuila.synkro.auth.application.port.out.PasswordHasher;
import co.edu.corhuila.synkro.auth.application.port.out.PasswordResetAttemptLog;
import co.edu.corhuila.synkro.auth.application.port.out.PasswordResetAttemptLog.Reason;
import co.edu.corhuila.synkro.auth.application.port.out.PasswordResetStore;
import co.edu.corhuila.synkro.auth.application.port.out.PasswordResetStore.Outcome;
import co.edu.corhuila.synkro.auth.application.port.out.PasswordResetStore.Recorded;
import co.edu.corhuila.synkro.auth.application.port.out.PasswordResetStore.ResetAttribution;
import co.edu.corhuila.synkro.auth.application.port.out.UserRepository;
import co.edu.corhuila.synkro.auth.domain.model.AuthenticatedCaller;
import co.edu.corhuila.synkro.auth.domain.model.Roles;
import co.edu.corhuila.synkro.auth.domain.model.SystemUser;

import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.Locale;
import java.util.Optional;

/**
 * An ADMIN replaces the password of an active SALESPERSON or INVENTORY user (HU-AUTH-19, ADR-021). The order of the
 * checks is part of the contract: nothing below a check runs before it passes, so a caller that may not reset learns
 * nothing about a key, a target or the request.
 */
public class ResetUserPasswordUseCase {
    private final UserRepository users;
    private final PasswordResetStore resets;
    private final PasswordHasher hasher;
    private final IdGenerator ids;
    private final Clock clock;
    private final PasswordResetAttemptLog attempts;

    public ResetUserPasswordUseCase(UserRepository users, PasswordResetStore resets, PasswordHasher hasher,
                                    IdGenerator ids, Clock clock, PasswordResetAttemptLog attempts) {
        this.users = users;
        this.resets = resets;
        this.hasher = hasher;
        this.ids = ids;
        this.clock = clock;
        this.attempts = attempts;
    }

    public ResetUserPasswordResult execute(AuthenticatedCaller caller, String correlationId, ResetUserPasswordCommand command) {
        try {
            return reset(caller, correlationId, command);
        } catch (RuntimeException e) {
            attempts.rejected(correlationId, caller == null ? null : caller.subject(), loggableTarget(command), reasonOf(e));
            throw e;
        }
    }

    /** Authorizes the transport before it decodes input; execute also checks again before any reset or replay. */
    public void authorizeBeforeDecoding(AuthenticatedCaller caller, String correlationId) {
        try {
            requireHumanAdmin(caller);
            requireActiveActor(caller);
        } catch (RuntimeException failure) {
            attempts.rejected(correlationId, caller == null ? null : caller.subject(), null, reasonOf(failure));
            throw failure;
        }
    }

    private ResetUserPasswordResult reset(AuthenticatedCaller caller, String correlationId, ResetUserPasswordCommand command) {
        requireHumanAdmin(caller);
        requireActiveActor(caller);
        ResetUserPasswordValidator.validate(command);
        String targetId = command.targetUserId().toLowerCase(Locale.ROOT);

        // The key comes before the target: a retry must find its answer even though the target would now be refused.
        Optional<Recorded> original = resets.findByActorAndKey(caller.subject(), command.idempotencyKey());
        if (original.isPresent()) {
            return replay(command, targetId, original.get());
        }
        requireEligible(targetId);

        // Hashed before the unit starts, so no lock is held while bcrypt works. PostgreSQL keeps microseconds:
        // truncating here makes the answer equal what a later replay reads back.
        String newHash = hasher.hash(command.newPassword());
        ResetAttribution attribution = new ResetAttribution(ids.newId(), caller.subject(),
            clock.instant().truncatedTo(ChronoUnit.MICROS), correlationId);
        Outcome outcome = resets.resetPasswordWithAudit(command.idempotencyKey(), targetId, newHash, attribution);
        return switch (outcome) {
            case Outcome.Reset done -> new ResetUserPasswordResult(targetId, done.occurredAt(), false);
            case Outcome.AlreadyRecorded raced -> replay(command, targetId, raced.record());
            case Outcome.TargetNotEligible gone -> throw notEligible("The user can no longer be reset");
        };
    }

    // Authorization comes before anything else, the key lookup included: a caller that may not reset must learn
    // nothing about a key, so a replay is refused exactly like a first attempt.
    private static void requireHumanAdmin(AuthenticatedCaller caller) {
        if (caller == null) {
            throw new UnauthenticatedException();
        }
        if (caller.isService()) {
            throw new ForbiddenException("A service is not authorized to reset passwords");
        }
        RoleGuard.requireAnyRole(caller, "reset passwords", Roles.ADMIN);
    }

    // The token proves who the administrator is, not that the account is still there or still active. Resetting is
    // stricter than registering: a deactivated administrator is refused too. A lookup that fails is not an absent
    // actor: its exception propagates as a failure.
    private void requireActiveActor(AuthenticatedCaller caller) {
        boolean usable = users.findById(caller.subject()).map(SystemUser::isActive).orElse(false);
        if (!usable) {
            throw new ForbiddenException("The caller is not authorized to reset passwords");
        }
    }

    // The same conditions are enforced again inside the unit, so a target that changes in between is still refused.
    private void requireEligible(String targetId) {
        SystemUser target = users.findById(targetId).orElseThrow(() -> new NotFoundException("Resource not found"));
        if (Roles.ADMIN.equals(target.getRole())) {
            throw notEligible("The password of an administrator cannot be reset");
        }
        if (!target.isActive()) {
            throw notEligible("The password of an inactive user cannot be reset");
        }
    }

    // A key is only an answer to the request that created it: made by this actor, for one target, with the password that
    // request set. That password is compared with the private receipt of that very reset (the bcrypt it stored, which
    // lives 24 hours), never with the target's current hash: a later reset by another key changes the current hash but
    // not what this key did. Without a valid receipt (expired, cleaned up or never written) the request cannot be
    // recognised and is refused; the key stays consumed and nothing is executed again. Replay is read-only: the target
    // is not even read.
    private ResetUserPasswordResult replay(ResetUserPasswordCommand command, String targetId, Recorded original) {
        boolean sameRequest = original.targetUserId().equalsIgnoreCase(targetId)
            && original.receipt()
                .map(receipt -> hasher.matches(command.newPassword(), receipt.passwordHash()))
                .orElse(false);
        if (!sameRequest) {
            throw new BusinessRuleViolationException(ResetUserPasswordValidator.IDEMPOTENCY_KEY,
                "The Idempotency-Key was already used with a different request");
        }
        return new ResetUserPasswordResult(original.targetUserId(), original.occurredAt(), true);
    }

    private static BusinessRuleViolationException notEligible(String message) {
        return new BusinessRuleViolationException(ResetUserPasswordValidator.TARGET, message);
    }

    // Only a well-formed identifier is copied into the log: anything else the caller typed stays out of it.
    private static String loggableTarget(ResetUserPasswordCommand command) {
        if (command == null || !ResetUserPasswordValidator.isIdentifier(command.targetUserId())) {
            return null;
        }
        return command.targetUserId().toLowerCase(Locale.ROOT);
    }

    private static Reason reasonOf(RuntimeException failure) {
        if (failure instanceof UnauthenticatedException) {
            return Reason.UNAUTHENTICATED;
        }
        if (failure instanceof ForbiddenException) {
            return Reason.FORBIDDEN;
        }
        if (failure instanceof ValidationException) {
            return Reason.INVALID_REQUEST;
        }
        if (failure instanceof NotFoundException) {
            return Reason.NOT_FOUND;
        }
        if (failure instanceof BusinessRuleViolationException) {
            return Reason.BUSINESS_RULE;
        }
        return Reason.FAILED;
    }
}
