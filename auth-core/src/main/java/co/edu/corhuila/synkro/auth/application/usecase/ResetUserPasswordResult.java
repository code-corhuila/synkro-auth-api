package co.edu.corhuila.synkro.auth.application.usecase;

import java.time.Instant;

/**
 * @param replayed true when the key had already been used by an equivalent request: the answer is the first
 *                 execution's, and nothing was changed this time
 */
public record ResetUserPasswordResult(String userId, Instant passwordResetAt, boolean replayed) {
}
