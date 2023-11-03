package be.oniryx.springsecurityaot;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.oauth2Login(oauth2 -> oauth2.loginPage("/api/login")
                        .loginProcessingUrl("/api/login/oauth2/code/microsoft") // Process return from microsoft
                        .authorizationEndpoint(authorizationEndpointConfig -> authorizationEndpointConfig
                                .baseUri("/api/oauth2/authorization")))
                .exceptionHandling(exception -> exception
                        .defaultAuthenticationEntryPointFor((request, response, authException) -> {
                            if (request.getRequestURI().equals("/api/login")) {
                                response.sendRedirect("/api/oauth2/authorization/microsoft"); // Authenticate with microsoft
                            } else {
                                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                                response.setContentType("application/json");
                                response.getWriter().write("{\"error\":\"" + authException.getMessage() + "\"}");
                            }
                        }, AntPathRequestMatcher.antMatcher("/api/**")))
                .authorizeHttpRequests(authorizeRequests -> authorizeRequests
                        .requestMatchers("/api/**").fullyAuthenticated()
                        .anyRequest().permitAll())
                .csrf(csrf -> csrf.csrfTokenRepository(csrfRepository()));
        return http.build();
    }

    private CsrfTokenRepository csrfRepository() {
        HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
        repository.setHeaderName("X-XSRF-TOKEN");
        return repository;
    }
}
