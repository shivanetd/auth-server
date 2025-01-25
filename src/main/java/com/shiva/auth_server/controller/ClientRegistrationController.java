package com.shiva.auth_server.controller;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.UUID;

@RestController
@RequestMapping("/api/clients")
public class ClientRegistrationController {
    private final RegisteredClientRepository clientRepository;

    public ClientRegistrationController(RegisteredClientRepository clientRepository) {
        this.clientRepository = clientRepository;
    }

    @PostMapping("/register")
    public String registerClient(@RequestBody ClientRegistrationRequest request) {
        RegisteredClient registeredClient = RegisteredClient
            .withId(UUID.randomUUID().toString())
            .clientId(request.clientId())
            .clientSecret(request.clientSecret())
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .redirectUri(request.redirectUri())
            .clientIdIssuedAt(Instant.now())
            .clientName(request.clientName())
            .scope("read")
            .scope("write")
            .build();

        clientRepository.save(registeredClient);
        return "Client registered successfully: " + registeredClient.getClientId();
    }

    public record ClientRegistrationRequest(
        String clientId, 
        String clientSecret, 
        String redirectUri, 
        String clientName
    ) {}
}