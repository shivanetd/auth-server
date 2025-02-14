package com.shiva.auth_server.model;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import lombok.Getter;
import lombok.Setter;

import java.time.Instant;

@Document(collection = "oauth2_authorizations")
@Getter @Setter
public class OAuth2AuthorizationModel {
    @Id
    private String id;
    private String registeredClientId;
    private String principalName;
    private String authorizationGrantType;
    private String authorizationCode;
    private Instant authorizationCodeIssuedAt;
    private Instant authorizationCodeExpiresAt;
    private String state;

    // Getters and setters
}