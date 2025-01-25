package com.shiva.auth_server.model;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@Document(collection = "jwt_keys")
public class JwtKey {
    @Id
    private String id;
    private String publicKey;
    private String privateKey;
    private boolean active;

    // Getters and setters
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getPublicKey() { return publicKey; }
    public void setPublicKey(String publicKey) { this.publicKey = publicKey; }
    public String getPrivateKey() { return privateKey; }
    public void setPrivateKey(String privateKey) { this.privateKey = privateKey; }
    public boolean isActive() { return active; }
    public void setActive(boolean active) { this.active = active; }
}