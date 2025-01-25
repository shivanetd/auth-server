package com.shiva.auth_server.model;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.time.Instant;
import java.util.Set;
import java.util.stream.Collectors;

@Document(collection = "registered_clients")
public class CustomRegisteredClient {
    @Id
    private String id;
    private String clientId;
    private Instant clientIdIssuedAt;
    private String clientSecret;
    private Instant clientSecretExpiresAt;
    private String clientName;
    private Set<String> clientAuthenticationMethods;
    private Set<String> authorizationGrantTypes;
    private Set<String> redirectUris;
    private Set<String> scopes;

    public static CustomRegisteredClient fromRegisteredClient(RegisteredClient registeredClient) {
        CustomRegisteredClient mongoClient = new CustomRegisteredClient();
        mongoClient.setId(registeredClient.getId());
        mongoClient.setClientId(registeredClient.getClientId());
        mongoClient.setClientIdIssuedAt(registeredClient.getClientIdIssuedAt());
        mongoClient.setClientSecret(registeredClient.getClientSecret());
        mongoClient.setClientSecretExpiresAt(registeredClient.getClientSecretExpiresAt());
        mongoClient.setClientName(registeredClient.getClientName());
        
        mongoClient.setClientAuthenticationMethods(
            registeredClient.getClientAuthenticationMethods().stream()
                .map(ClientAuthenticationMethod::getValue)
                .collect(Collectors.toSet())
        );
        
        mongoClient.setAuthorizationGrantTypes(
            registeredClient.getAuthorizationGrantTypes().stream()
                .map(AuthorizationGrantType::getValue)
                .collect(Collectors.toSet())
        );
        
        mongoClient.setRedirectUris(registeredClient.getRedirectUris());
        mongoClient.setScopes(registeredClient.getScopes());
        
        return mongoClient;
    }

    public RegisteredClient toRegisteredClient() {
        return RegisteredClient.withId(this.id)
            .clientId(this.clientId)
            .clientIdIssuedAt(this.clientIdIssuedAt)
            .clientSecret(this.clientSecret)
            .clientSecretExpiresAt(this.clientSecretExpiresAt)
            .clientName(this.clientName)
            .clientAuthenticationMethods(methods -> 
                this.clientAuthenticationMethods.forEach(method -> 
                    methods.add(new ClientAuthenticationMethod(method))
                )
            )
            .authorizationGrantTypes(grants -> 
                this.authorizationGrantTypes.forEach(grant -> 
                    grants.add(new AuthorizationGrantType(grant))
                )
            )
            .redirectUris(uris -> uris.addAll(this.redirectUris))
            .scopes(scopeSet -> scopeSet.addAll(this.scopes))
            .build();
    }

    // Getters and Setters
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getClientId() { return clientId; }
    public void setClientId(String clientId) { this.clientId = clientId; }
    public Instant getClientIdIssuedAt() { return clientIdIssuedAt; }
    public void setClientIdIssuedAt(Instant clientIdIssuedAt) { this.clientIdIssuedAt = clientIdIssuedAt; }
    public String getClientSecret() { return clientSecret; }
    public void setClientSecret(String clientSecret) { this.clientSecret = clientSecret; }
    public Instant getClientSecretExpiresAt() { return clientSecretExpiresAt; }
    public void setClientSecretExpiresAt(Instant clientSecretExpiresAt) { this.clientSecretExpiresAt = clientSecretExpiresAt; }
    public String getClientName() { return clientName; }
    public void setClientName(String clientName) { this.clientName = clientName; }
    public Set<String> getClientAuthenticationMethods() { return clientAuthenticationMethods; }
    public void setClientAuthenticationMethods(Set<String> clientAuthenticationMethods) { this.clientAuthenticationMethods = clientAuthenticationMethods; }
    public Set<String> getAuthorizationGrantTypes() { return authorizationGrantTypes; }
    public void setAuthorizationGrantTypes(Set<String> authorizationGrantTypes) { this.authorizationGrantTypes = authorizationGrantTypes; }
    public Set<String> getRedirectUris() { return redirectUris; }
    public void setRedirectUris(Set<String> redirectUris) { this.redirectUris = redirectUris; }
    public Set<String> getScopes() { return scopes; }
    public void setScopes(Set<String> scopes) { this.scopes = scopes; }
}