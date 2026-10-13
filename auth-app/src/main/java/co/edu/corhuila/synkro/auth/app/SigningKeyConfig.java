package co.edu.corhuila.synkro.auth.app;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.PrivateKey;

@Configuration
public class SigningKeyConfig {

    // No default on purpose: an unset variable fails placeholder resolution, a blank or
    // unreadable one fails inside KeyLoader. Either way the context never starts.
    @Bean
    public PrivateKey jwtPrivateKey(@Value("${JWT_PRIVATE_KEY_FILE}") String keyFile) {
        return KeyLoader.loadPrivateKey(keyFile);
    }
}
