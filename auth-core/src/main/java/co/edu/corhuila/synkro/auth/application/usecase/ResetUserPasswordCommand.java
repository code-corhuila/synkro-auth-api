package co.edu.corhuila.synkro.auth.application.usecase;

/**
 * Raw input, unchecked: the use case is the single place that validates it. The two passwords are secrets, so the
 * generated {@code toString} is replaced: a command that reaches a log, an assertion message or a debugger prints
 * only what is not secret.
 */
public record ResetUserPasswordCommand(String targetUserId, String idempotencyKey, String newPassword,
                                       String confirmPassword) {

    @Override
    public String toString() {
        return "ResetUserPasswordCommand[targetUserId=" + targetUserId + ", newPassword=<redacted>, confirmPassword=<redacted>]";
    }
}
