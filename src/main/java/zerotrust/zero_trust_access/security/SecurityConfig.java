package zerotrust.zero_trust_access.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    private final SessionAuthFilter sessionAuthFilter;
    private final SessionService sessionService;

    @Bean
    // wherever hashing or password check is needed for injection
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // targets login and register for non authentication and catches everything else
        // turn off csrf because no cookies are being used

        http.csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth.requestMatchers("/auth/login", "/auth/register")
                        .permitAll().anyRequest().authenticated())
                .addFilterBefore(sessionAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();

    }

    public SecurityConfig(SessionService sessionService, SessionAuthFilter sessionAuthFilter) {
        this.sessionService = sessionService;
        this.sessionAuthFilter = sessionAuthFilter;
    }
}
