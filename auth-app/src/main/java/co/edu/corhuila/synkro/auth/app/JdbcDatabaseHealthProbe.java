package co.edu.corhuila.synkro.auth.app;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.Duration;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * Reads one row of auth_schema.system_user as auth_app: it proves the connection, the credentials and the schema, not
 * only that something answers on the port. A check that has not finished within the limit counts as down, and at
 * most a few checks wait on the pool at once, so a database that hangs cannot pile up threads.
 */
class JdbcDatabaseHealthProbe implements DatabaseHealthProbe {

    private static final Logger LOG = LoggerFactory.getLogger(JdbcDatabaseHealthProbe.class);
    private static final String CHECK = "SELECT 1 FROM auth_schema.system_user LIMIT 1";
    private static final int MAX_CONCURRENT_CHECKS = 4;

    private final JdbcTemplate jdbc;
    private final Duration limit;
    private final ExecutorService checks = new ThreadPoolExecutor(0, MAX_CONCURRENT_CHECKS, 10, TimeUnit.SECONDS,
        new SynchronousQueue<>(), runnable -> {
            Thread thread = new Thread(runnable, "auth-health-check");
            thread.setDaemon(true);
            return thread;
        });

    JdbcDatabaseHealthProbe(JdbcTemplate jdbc, Duration limit) {
        this.jdbc = jdbc;
        this.limit = limit;
    }

    @Override
    public boolean isReachable() {
        Future<?> check;
        try {
            check = checks.submit(() -> jdbc.queryForList(CHECK));
        } catch (RejectedExecutionException saturated) {
            LOG.warn("health: auth_schema check not run, {} checks are already waiting", MAX_CONCURRENT_CHECKS);
            return false;
        }
        try {
            check.get(limit.toMillis(), TimeUnit.MILLISECONDS);
            return true;
        } catch (InterruptedException interrupted) {
            check.cancel(true);
            Thread.currentThread().interrupt();
            return false;
        } catch (Exception failed) {
            check.cancel(true);
            // Only the kind of failure: a driver message can carry the host, the user or the URL.
            LOG.warn("health: auth_schema is not reachable ({})", failed instanceof java.util.concurrent.ExecutionException && failed.getCause() != null
                ? failed.getCause().getClass().getSimpleName() : failed.getClass().getSimpleName());
            return false;
        }
    }
}
