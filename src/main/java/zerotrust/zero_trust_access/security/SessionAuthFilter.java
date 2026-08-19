package zerotrust.zero_trust_access.security;

import java.io.IOException;
import java.util.Collections;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import zerotrust.zero_trust_access.model.User;
import zerotrust.zero_trust_access.repository.UserRepository;

@Component
public class SessionAuthFilter extends OncePerRequestFilter {
    private final SessionService sessionService;
    private final UserRepository userRepository;

    // inherated abstract method
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        // get auth
        String authHeader = request.getHeader("Authorization");
        // bearer is the format label that stores token
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        // verifies token is valid
        String token = authHeader.substring(7);

        String username = sessionService.validateSession(token);
        // if username null let reuqest continue authenticated
        if (username == null) {
            filterChain.doFilter(request, response);
            return;
        }
        User user = userRepository.findByUsername(username).orElseThrow();
        // treat as a logged in user
        SecurityContextHolder.getContext()
                .setAuthentication(new UsernamePasswordAuthenticationToken(user, null, Collections.emptyList()));
        filterChain.doFilter(request, response);
    }

    public SessionAuthFilter(SessionService sessionService, UserRepository userRepository) {
        this.sessionService = sessionService;
        this.userRepository = userRepository;
    }
}
