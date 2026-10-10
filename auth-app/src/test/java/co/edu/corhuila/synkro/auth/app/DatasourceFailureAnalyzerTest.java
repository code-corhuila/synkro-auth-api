package co.edu.corhuila.synkro.auth.app;

import org.junit.jupiter.api.Test;
import org.springframework.boot.diagnostics.FailureAnalysis;

import static org.assertj.core.api.Assertions.assertThat;

class DatasourceFailureAnalyzerTest {

    private final DatasourceFailureAnalyzer analyzer = new DatasourceFailureAnalyzer();

    @Test
    void aDatasourceConfigurationFailure_buriedUnderBeanCreationErrors_isReportedByItsOwnMessage() {
        Throwable failure = new IllegalStateException("Error creating bean with name 'jdbcTemplate'",
            new IllegalStateException("Error creating bean with name 'dataSource'",
                new DatasourceConfigurationException("SPRING_DATASOURCE_URL is not set")));

        FailureAnalysis analysis = analyzer.analyze(failure);

        assertThat(analysis).isNotNull();
        assertThat(analysis.getDescription()).isEqualTo("SPRING_DATASOURCE_URL is not set");
        assertThat(analysis.getAction())
            .contains("SPRING_DATASOURCE_URL", "SPRING_DATASOURCE_USERNAME", "SPRING_DATASOURCE_PASSWORD_FILE");
    }

    @Test
    void anyOtherFailure_isLeftToTheDefaultReporting() {
        assertThat(analyzer.analyze(new IllegalStateException("something else"))).isNull();
    }

    @Test
    void settingsThatAreInvalid_throwTheDedicatedException() {
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> DatasourceSettings.resolve("", "auth_app", "x", ""))
            .isInstanceOf(DatasourceConfigurationException.class);
    }
}
