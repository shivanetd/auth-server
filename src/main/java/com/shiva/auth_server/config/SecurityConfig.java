package com.shiva.auth_server.config;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.UUID;

import org.springframework.core.annotation.Order;
import org.springframework.core.Ordered;
import org.springframework.context.annotation.Configuration;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.shiva.auth_server.service.JwtKeyService;


@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtKeyService jwtKeyService;

    public SecurityConfig(JwtKeyService jwtKeyService) {
        this.jwtKeyService = jwtKeyService;
    }

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception{

        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
            .oidc(Customizer.withDefaults());
        
        http
            .exceptionHandling(exceptions -> 
                exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
            )
            .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
        
        return http.build();

    }


    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/login").permitAll()
                .requestMatchers("/oauth2/authorize").permitAll()
                .requestMatchers("/oauth2/token").permitAll()
                .anyRequest().authenticated()
            )
            .formLogin(Customizer.withDefaults());
    
    return http.build();
    }

    // @Bean
    // public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
    //     UserDetails userDetails = User.withUsername("user")
    //         .password(passwordEncoder.encode("password"))
    //         .roles("USER")
    //         .build();

    //     return new InMemoryUserDetailsManager(userDetails);
    // }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
            .issuer("http://localhost:8080")
            .build();
    }

    // @Bean
    // public Algorithm jwtAlgorithm() {
    //     return Algorithm.RSA256(publicKey, privateKey);
    // }


    @Bean
    public Algorithm jwtAlgorithm() {
        KeyPair keyPair = jwtKeyService.getOrCreateKeyPair();
        return Algorithm.RSA256((RSAPublicKey) keyPair.getPublic(), (RSAPrivateKey) keyPair.getPrivate());
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withPublicKey((RSAPublicKey) jwtKeyService.getOrCreateKeyPair().getPublic()).build();
    }

    // @Bean
    // public PasswordEncoder passwordEncoder() {
    //     return new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder();
    // }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new PasswordEncoder() {
            @Override
            public String encode(CharSequence rawPassword) {
                return rawPassword.toString();
            }

            @Override
            public boolean matches(CharSequence rawPassword, String encodedPassword) {
                return rawPassword.toString().equals(encodedPassword);
            }
        };
    }


    // Example method to demonstrate Auth0 JWT token generation
    public String generateToken(String username) {
        return JWT.create()
            .withSubject(username)
            .withIssuer("http://localhost:8080")
            .withIssuedAt(new Date())
            .withExpiresAt(new Date(System.currentTimeMillis() + 86400000)) // 24 hours
            .withJWTId(UUID.randomUUID().toString())
            .sign(jwtAlgorithm());
    }


    @Bean
    public CommandLineRunner debugClientConfiguration(RegisteredClientRepository repository){
        return args -> {
            try {
                RegisteredClient client = repository.findByClientId("my-client-app");
                if (client != null) {
                    System.out.println("Client Details:");
                    System.out.println("Client ID: " + client.getClientId());
                    System.out.println("Authentication Methods: " + client.getClientAuthenticationMethods());
                    System.out.println("Grant Types: " + client.getAuthorizationGrantTypes());
                } else {
                    System.out.println("No client found with ID: client-credentials-client");
                }
            } catch (Exception e) {
                System.err.println("Error retrieving client: " + e.getMessage());
            }
        };
    }

}