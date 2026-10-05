package co.edu.corhuila.synkro.auth.app;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;

// No username/password login exists in this service's security chain, so Boot's
// default in-memory user (and its generated password) is excluded.
@SpringBootApplication(exclude = UserDetailsServiceAutoConfiguration.class)
public class AuthApiApplication {
    public static void main(String[] args) {
        SpringApplication.run(AuthApiApplication.class, args);
    }
}
