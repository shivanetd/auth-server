package com.shiva.auth_server.service;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;
import org.springframework.stereotype.Service;

import com.shiva.auth_server.model.JwtKey;

import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Optional;

@Service
public class JwtKeyService {
    private final JwtKeyRepository keyRepository;

    public JwtKeyService(JwtKeyRepository keyRepository) {
        this.keyRepository = keyRepository;
    }

    public KeyPair getOrCreateKeyPair() {
        JwtKey jwtKey = keyRepository.findByActiveTrue()
            .orElseGet(this::generateAndSaveNewKeyPair);

        return convertToKeyPair(jwtKey);
    }

    private JwtKey generateAndSaveNewKeyPair() {
        KeyPair keyPair = generateRsaKey();
        JwtKey jwtKey = new JwtKey();
        jwtKey.setPublicKey(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
        jwtKey.setPrivateKey(Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
        jwtKey.setActive(true);
        return keyRepository.save(jwtKey);
    }

    private KeyPair convertToKeyPair(JwtKey jwtKey){
        try {
            byte[] publicKeyBytes = Base64.getDecoder().decode(jwtKey.getPublicKey());
            byte[] privateKeyBytes = Base64.getDecoder().decode(jwtKey.getPrivateKey());

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
            
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
            
            return new KeyPair(publicKey, privateKey);
        } catch (Exception e) {
            throw new RuntimeException("Error deserializing key pair", e);
        }
    }

    private KeyPair generateRsaKey() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }
}

@Repository
interface JwtKeyRepository extends MongoRepository<JwtKey, String> {
    Optional<JwtKey> findByActiveTrue();
}