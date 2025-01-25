package com.shiva.auth_server.config;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;


@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private RSAPrivateKey privateKey;
    private RSAPublicKey publicKey;

    public SecurityConfig(){
        KeyPair keyPair = generateRsaKey();
        privateKey = (RSAPrivateKey) keyPair.getPrivate();
        publicKey = (RSAPublicKey) keyPair.getPublic();
    }


    private static KeyPair generateRsaKey(){
        KeyPair keyPair;

        try{
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA"); 
            generator.initialize(2048);
            keyPair = generator.generateKeyPair();
        } catch(Exception ex){
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

}