package co.edu.corhuila.synkro.auth.app;

/** A datasource setting is missing or unusable. The message names the variable, never a value. */
class DatasourceConfigurationException extends IllegalStateException {

    DatasourceConfigurationException(String message) {
        super(message);
    }
}
