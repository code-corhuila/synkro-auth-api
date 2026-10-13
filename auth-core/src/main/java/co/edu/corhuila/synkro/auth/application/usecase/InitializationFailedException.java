package co.edu.corhuila.synkro.auth.application.usecase;

/**
 * The initialization could not be completed for a reason outside the input. It carries only the kind of failure
 * and the SQLSTATE: never the driver's message (it may repeat a connection URL), a cause chain or any input.
 */
public class InitializationFailedException extends RuntimeException {

    public enum Kind {
        /** The advisory lock was not obtained within the wait; nothing was written. */
        LOCK_TIMEOUT,
        /** The database refused or lost the work before the commit; nothing was kept. */
        DATABASE,
        /** The commit was sent but its confirmation never arrived: the administrator may or may not exist. */
        OUTCOME_UNCERTAIN
    }

    private final Kind kind;
    private final String sqlState;

    public InitializationFailedException(Kind kind, String sqlState) {
        super(describe(kind, sqlState));
        this.kind = kind;
        this.sqlState = sqlState == null || sqlState.isBlank() ? "unknown" : sqlState;
    }

    public Kind kind() {
        return kind;
    }

    public String sqlState() {
        return sqlState;
    }

    private static String describe(Kind kind, String sqlState) {
        String state = sqlState == null || sqlState.isBlank() ? "unknown" : sqlState;
        return switch (kind) {
            case LOCK_TIMEOUT -> "The initialization lock was not obtained in time (SQLSTATE " + state + ")";
            case DATABASE -> "The database failed during the initialization (SQLSTATE " + state + ")";
            case OUTCOME_UNCERTAIN -> "The outcome of the initialization is uncertain (SQLSTATE " + state + ")";
        };
    }
}
