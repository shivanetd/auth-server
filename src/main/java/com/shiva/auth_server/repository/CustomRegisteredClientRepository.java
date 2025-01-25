package com.shiva.auth_server.repository;

import java.util.Optional;

import org.springframework.data.mongodb.repository.MongoRepository;

import com.shiva.auth_server.model.CustomRegisteredClient;

public interface CustomRegisteredClientRepository extends MongoRepository<CustomRegisteredClient, String>  {
    Optional<CustomRegisteredClient> findByClientId(String clientId);
}
