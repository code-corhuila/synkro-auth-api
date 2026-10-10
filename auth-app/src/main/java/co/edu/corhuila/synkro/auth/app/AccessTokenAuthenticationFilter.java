package co.edu.corhuila.synkro.auth.app;

import co.edu.corhuila.synkro.auth.application.port.out.AccessTokenVerifier;
import co.edu.corhuila.synkro.auth.application.usecase.InvalidTokenException;
import co.edu.corhuila.synkro.auth.domain.model.AuthenticatedCaller;
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
 * Turns a verified Bearer token into the authenticated caller. A missing or invalid token
 * leaves the request anonymous: the authorization rules then answer 401 on protected routes
 * and let public ones through. Only the token is read; X-User-* headers are never consulted.
 */
class AccessTokenAuthenticationFilter extends OncePerRequestFilter {
    private static final String BEARER = "Bearer ";

    private final AccessTokenVerifier verifier;

    AccessTokenAuthenticationFilter(AccessTokenVerifier verifier) {
        this.verifier = verifier;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        if (header != null && header.regionMatches(true, 0, BEARER, 0, BEARER.length())) {
            try {
                AuthenticatedCaller caller = verifier.verify(header.substring(BEARER.length()).trim());
                SecurityContextHolder.getContext().setAuthentication(
                    UsernamePasswordAuthenticationToken.authenticated(caller, null, List.of()));
            } catch (InvalidTokenException e) {
                SecurityContextHolder.clearContext();
            }
        }
        chain.doFilter(request, response);
    }
}
