package co.edu.corhuila.synkro.auth.app;

import com.zaxxer.hikari.HikariDataSource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * The service's only database connection: PostgreSQL as auth_app. The pool is built here, not
 * by Boot's auto-configuration, so a missing or unusable setting fails the startup with a message
 * that names the variable. Pool limits come from spring.datasource.hikari.* (application.yml).
 * Nothing here connects: the first connection is made by the first request.
 */
@Configuration
public class DatabaseConfig {

    @Bean
    @ConfigurationProperties("spring.datasource.hikari")
    public HikariDataSource dataSource(@Value("${spring.datasource.url:}") String url,
                                       @Value("${spring.datasource.username:}") String username,
                                       @Value("${spring.datasource.password:}") String password,
                                       @Value("${spring.datasource.password-file:}") String passwordFile) {
        DatasourceSettings settings = DatasourceSettings.resolve(url, username, password, passwordFile);
        HikariDataSource dataSource = new HikariDataSource();
        dataSource.setPoolName("auth-db");
        dataSource.setJdbcUrl(settings.url());
        dataSource.setUsername(settings.username());
        dataSource.setPassword(settings.password());
        return dataSource;
    }
}
