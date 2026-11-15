package co.edu.corhuila.synkro.auth.application.port.out;

import co.edu.corhuila.synkro.auth.domain.model.SystemUser;

import java.time.Instant;
import java.util.Optional;

/**
 * Persistence of the refresh credential of a login (HU-AUTH-19, ADR-021 Decision 3, login issuance fencing).
 *
 * <p>A login verifies the password outside any lock, because bcrypt is slow, and only then asks this port to persist
 * the credential. A password reset that committed in between must win: the credential would otherwise be issued from a
 * password snapshot that no longer exists. So the port decides, in one transaction under the same per-user lock that a
 * reset and a refresh rotation take, whether the verification still stands.
 */
public interface CredentialIssuanceStore {

    /**
     * In one transaction: takes the per-user lock shared with password reset and refresh rotation, reads the current
     * user, and only if that user exists, is active and still stores exactly {@code verifiedPasswordHash} saves the
     * refresh credential and commits before returning.
     *
     * @param verifiedPasswordHash the stored hash that the login verified the password against
     * @return the current identity (the claims to issue) when the credential was saved; empty when the user is gone,
     *         inactive or has a different hash, in which case nothing was saved and the login must fail with the same
     *         generic error as a wrong password
     */
    Optional<SystemUser> persistRefresh(String userId, String verifiedPasswordHash, String refreshTokenHash, Instant expiresAt);
}
