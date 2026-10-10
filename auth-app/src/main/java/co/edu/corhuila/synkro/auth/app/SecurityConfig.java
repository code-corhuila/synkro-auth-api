package co.edu.corhuila.synkro.auth.app;

import co.edu.corhuila.synkro.auth.application.port.out.AccessTokenVerifier;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.DispatcherType;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, AccessTokenVerifier verifier, ObjectMapper json) throws Exception {
        SecurityErrorResponses errors = new SecurityErrorResponses(json);
        http
            .csrf(csrf -> csrf.disable())
            .httpBasic(basic -> basic.disable())
            .formLogin(form -> form.disable())
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                // Error rendering happens on a second (ERROR) dispatch to /error, after the
                // stateless context of the original request has been cleared. Without this,
                // that dispatch is anonymous and every 404/405/500 is masked as a 401.
                // Only the ERROR dispatch is permitted; a direct request to /error is not.
                .dispatcherTypeMatchers(DispatcherType.ERROR).permitAll()
                .requestMatchers("/health").permitAll()
                // Public by design (ADR-001 §8): the caller has no access token yet, by definition.
                .requestMatchers(HttpMethod.POST, "/api/v1/auth/login", "/api/v1/auth/refresh").permitAll()
                .anyRequest().authenticated()
            )
            // Not a bean: a Filter bean would also be registered in the servlet container, outside this chain.
            .addFilterBefore(new AccessTokenAuthenticationFilter(verifier), UsernamePasswordAuthenticationFilter.class)
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint(errors.entryPoint())
                .accessDeniedHandler(errors.accessDeniedHandler()));
        return http.build();
    }
}
