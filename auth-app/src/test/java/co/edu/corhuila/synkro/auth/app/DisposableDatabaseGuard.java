package co.edu.corhuila.synkro.auth.app;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.regex.Pattern;

/**
 * Proof of identity required before a test empties auth_schema. The opt-in flag and the administrator password
 * show consent; this shows <em>which</em> database is on the other end: the exclusive name the operator declared
 * (TEST_DISPOSABLE_DATABASE_NAME) must live in the reserved {@code synkro_auth_disposable_} namespace and must
 * equal what the server itself reports from {@code current_database()} on the administrative connection. The URL is
 * not trusted for this: a proxy, an alias or a copied connection string can name one database and reach another.
 *
 * Any mismatch throws {@link AssertionError} before a single statement that modifies data is sent.
 * (A copy of the rule in the adapters module's tests: the modules share no test sources.)
 */
final class DisposableDatabaseGuard {

    static final String NAME_VARIABLE = "TEST_DISPOSABLE_DATABASE_NAME";
    static final String REQUIRED_PREFIX = "synkro_auth_disposable_";

    private static final Pattern NAME = Pattern.compile("^" + REQUIRED_PREFIX + "[a-z0-9_]+$");

    private DisposableDatabaseGuard() {}

    static void requireIdentity(String expectedName, String actualDatabase) {
        if (expectedName == null || expectedName.isBlank()) {
            throw new AssertionError(NAME_VARIABLE + " must name the disposable database (" + REQUIRED_PREFIX
                + "<suffix>): the cleanup empties auth_schema and refuses to run without proof of identity");
        }
        if (!NAME.matcher(expectedName).matches()) {
            throw new AssertionError("'" + expectedName + "' is not in the reserved disposable namespace "
                + REQUIRED_PREFIX + "<suffix>: refusing to empty auth_schema");
        }
        if (!expectedName.equals(actualDatabase)) {
            throw new AssertionError("The server reports database '" + actualDatabase + "', not the declared disposable '"
                + expectedName + "': refusing to empty auth_schema");
        }
    }

    /** Asks the server, on the administrative connection, which database this is. */
    static void requireDatabase(Connection admin, String expectedName) throws SQLException {
        String actual;
        try (Statement s = admin.createStatement(); ResultSet rs = s.executeQuery("SELECT current_database()")) {
            actual = rs.next() ? rs.getString(1) : null;
        }
        requireIdentity(expectedName, actual);
    }
}
