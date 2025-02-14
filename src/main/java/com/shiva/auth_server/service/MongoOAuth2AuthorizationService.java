package com.shiva.auth_server.service;


import java.util.Collections;

import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization.Token;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;

import com.shiva.auth_server.model.OAuth2AuthorizationModel;

import org.springframework.security.oauth2.core.AuthorizationGrantType;

@Service
public class MongoOAuth2AuthorizationService implements OAuth2AuthorizationService {
    private final MongoTemplate mongoTemplate;
    private final RegisteredClientRepository clientRepository;

    public MongoOAuth2AuthorizationService(MongoTemplate mongoTemplate, RegisteredClientRepository clientRepository) {
        this.mongoTemplate = mongoTemplate;
        this.clientRepository = clientRepository;
    }

    @Override
    public void save(OAuth2Authorization authorization) {
        mongoTemplate.save(convertToEntity(authorization));
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        mongoTemplate.remove(Query.query(Criteria.where("id").is(authorization.getId())), 
            OAuth2Authorization.class);
    }

    @Override
    public OAuth2Authorization findById(String id) {
        return convertToAuthorization(mongoTemplate.findById(id, OAuth2AuthorizationModel.class));
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        Query query = new Query();
        if (tokenType != null) {
            switch (tokenType.getValue()) {
                case "authorization_code":
                    query.addCriteria(Criteria.where("authorizationCode").is(token));
                    break;
                case "state":
                    query.addCriteria(Criteria.where("state").is(token));
                    break;
            }
        }
        return convertToAuthorization(mongoTemplate.findOne(query, OAuth2AuthorizationModel.class));
    }

    private OAuth2AuthorizationModel convertToEntity(OAuth2Authorization authorization) {
        OAuth2AuthorizationModel entity = 
            new OAuth2AuthorizationModel();
        entity.setId(authorization.getId());
        entity.setRegisteredClientId(authorization.getRegisteredClientId());
        entity.setPrincipalName(authorization.getPrincipalName());
        entity.setAuthorizationGrantType(
            authorization.getAuthorizationGrantType().getValue());
        
        if (authorization.getToken(OAuth2AuthorizationCode.class) != null) {
            Token<OAuth2AuthorizationCode> authCode = authorization.getToken(OAuth2AuthorizationCode.class);
            entity.setAuthorizationCode(authCode.getToken().getTokenValue());
            entity.setAuthorizationCodeIssuedAt(authCode.getToken().getIssuedAt());
            entity.setAuthorizationCodeExpiresAt(authCode.getToken().getExpiresAt());
        }
        
        entity.setState(authorization.getAttribute("state"));
        return entity;
    }

    private OAuth2Authorization convertToAuthorization(
            OAuth2AuthorizationModel entity) {
        if (entity == null) {
            return null;
        }

        RegisteredClient registeredClient = clientRepository.findById(entity.getRegisteredClientId());
        
        if (registeredClient == null) {
            throw new IllegalStateException("The RegisteredClient with id '" + entity.getRegisteredClientId() + "' was not found in the RegisteredClientRepository.");
        }

        OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(registeredClient)
            .id(entity.getId())
            .principalName(entity.getPrincipalName())
            .authorizationGrantType(new AuthorizationGrantType(entity.getAuthorizationGrantType()));

        if (entity.getState() != null) {
            builder.attribute("state", entity.getState());
        }

        if (entity.getAuthorizationCode() != null) {
            OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
                entity.getAuthorizationCode(),
                entity.getAuthorizationCodeIssuedAt(),
                entity.getAuthorizationCodeExpiresAt()
            );
            
            builder.token(authorizationCode, (metadata) -> {
                if (entity.getAuthorizationCodeIssuedAt() != null) {
                    metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, false);
                }
            });
        }

        return builder.build();
    }
}
