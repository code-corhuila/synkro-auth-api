package co.edu.corhuila.synkro.auth.app;

import org.springframework.boot.diagnostics.AbstractFailureAnalyzer;
import org.springframework.boot.diagnostics.FailureAnalysis;

/**
 * Replaces the wall of nested bean-creation errors that Spring prints for a bad datasource
 * with the one message that matters. Registered in META-INF/spring.factories.
 */
class DatasourceFailureAnalyzer extends AbstractFailureAnalyzer<DatasourceConfigurationException> {

    private static final String ACTION =
        "Set SPRING_DATASOURCE_URL, SPRING_DATASOURCE_USERNAME (it must be auth_app) and exactly one of "
            + "SPRING_DATASOURCE_PASSWORD or SPRING_DATASOURCE_PASSWORD_FILE. See \"Database\" in the README.";

    @Override
    protected FailureAnalysis analyze(Throwable rootFailure, DatasourceConfigurationException cause) {
        return new FailureAnalysis(cause.getMessage(), ACTION, cause);
    }
}
