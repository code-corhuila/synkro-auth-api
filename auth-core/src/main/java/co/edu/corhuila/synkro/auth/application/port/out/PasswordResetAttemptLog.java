package co.edu.corhuila.synkro.auth.application.port.out;

/**
 * Security log of password resets that did not happen. It is written outside the reset transaction and takes no request
 * data on purpose: only who asked, which request, which user it named when that parsed as an identifier, and why it
 * failed. Never a password, a hash, a key or the body.
 */
public interface PasswordResetAttemptLog {

    enum Reason { UNAUTHENTICATED, FORBIDDEN, INVALID_REQUEST, NOT_FOUND, BUSINESS_RULE, FAILED }

    /**
     * @param callerId     the verified caller's subject, or null when there was none
     * @param targetUserId the user the request named, only when it is a well-formed identifier, else null
     */
    void rejected(String correlationId, String callerId, String targetUserId, Reason reason);
}
