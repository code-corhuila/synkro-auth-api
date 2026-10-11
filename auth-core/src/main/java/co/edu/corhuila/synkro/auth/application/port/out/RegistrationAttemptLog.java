package co.edu.corhuila.synkro.auth.application.port.out;

/**
 * Security log of registrations that did not create a user. It is written outside the registration transaction and
 * takes no request data on purpose: only who asked, which request, and why it failed.
 */
public interface RegistrationAttemptLog {

    enum Reason { UNAUTHENTICATED, FORBIDDEN, INVALID_REQUEST, BUSINESS_RULE, FAILED }

    /** @param callerId the verified caller's subject, or null when there was none */
    void rejected(String correlationId, String callerId, Reason reason);
}
