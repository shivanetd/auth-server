package com.shiva.auth_server.service;

import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;

import com.shiva.auth_server.model.CustomRegisteredClient;
import com.shiva.auth_server.repository.CustomRegisteredClientRepository;

@Service
public class CustomRegisteredClientService implements RegisteredClientRepository {

    private final CustomRegisteredClientRepository clientRepository;

    public CustomRegisteredClientService(CustomRegisteredClientRepository clientRepository) {
        this.clientRepository = clientRepository;
    }
    @Override
    public void save(RegisteredClient registeredClient) {
        CustomRegisteredClient mongoClient = CustomRegisteredClient.fromRegisteredClient(registeredClient);
        clientRepository.save(mongoClient);
    }

    @Override
    public RegisteredClient findById(String id) {
        return clientRepository.findById(id)
            .map(CustomRegisteredClient::toRegisteredClient)
            .orElse(null);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        return clientRepository.findByClientId(clientId)
            .map(CustomRegisteredClient::toRegisteredClient)
            .orElse(null);
    }
    
}
