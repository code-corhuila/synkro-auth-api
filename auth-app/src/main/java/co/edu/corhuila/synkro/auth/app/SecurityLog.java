package co.edu.corhuila.synkro.auth.app;

import co.edu.corhuila.synkro.auth.application.port.out.RegistrationAttemptLog;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The security log of this service: one line per refused or failed attempt, with the correlation id to find the
 * request and nothing that came from its body. It is written after the fact and never joins a transaction.
 */
class SecurityLog implements RegistrationAttemptLog {

    static final String LOGGER_NAME = "synkro.auth.security";
    private static final Logger log = LoggerFactory.getLogger(LOGGER_NAME);

    @Override
    public void rejected(String correlationId, String callerId, Reason reason) {
        log.warn("security event=USER_REGISTRATION_REJECTED correlationId={} caller={} reason={}",
            correlationId, callerId == null ? "-" : callerId, reason);
    }

    /** A request the security chain refused before any use case ran (401 or 403). */
    static void accessRejected(int status, String method, String path, String correlationId) {
        log.warn("security event=ACCESS_REJECTED status={} method={} path={} correlationId={}", status, method, path, correlationId);
    }
}
