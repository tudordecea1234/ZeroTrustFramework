package com.example.zerotrustframework.authentication;


import com.example.zerotrustframework.common.UserService;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@ConditionalOnProperty(prefix="zero-trust.auth", name="enabled", value = "true")
@EnableConfigurationProperties(AuthenticationFilter.class)
public class AuthenticationAutoConfiguration {

    @Bean
    public AuthenticationFilter authFilter(TokenValidator tokenValidator, UserService userService){
        return new AuthenticationFilter(tokenValidator, userService);
    }

    @Bean
    public SecurityFilterChain SecurityFilterChain(HttpSecurity http, AuthenticationFilter authFilter, AuthenticationProperties authProperties) throws Exception {
        http.securityMatcher("/**").csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth.requestMatchers("/public/**").permitAll().anyRequest().authenticated())
                .addFilterBefore(authFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
