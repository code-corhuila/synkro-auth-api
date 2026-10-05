package co.edu.corhuila.synkro.auth.app;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * Deliberately minimal: only checks that a well-formed Bearer header is
 * present. Does NOT verify a signature, exp, or sub — real RS256
 * validation lands with the first story that needs an authenticated
 * request to actually succeed. Its only job is to make sure nothing is
 * reachable by accident.
 */
public class MinimalBearerCheckFilter extends OncePerRequestFilter {

    private static final String PREFIX = "Bearer ";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith(PREFIX) && header.length() > PREFIX.length()) {
            var auth = new UsernamePasswordAuthenticationToken("pending-validation", null, List.of());
            SecurityContextHolder.getContext().setAuthentication(auth);
        }
        chain.doFilter(request, response);
    }
}
