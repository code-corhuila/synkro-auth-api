package co.edu.corhuila.synkro.auth.app;

/** Whether the service can reach the schema it owns. Answers within a bounded time and never throws. */
public interface DatabaseHealthProbe {
    boolean isReachable();
}
