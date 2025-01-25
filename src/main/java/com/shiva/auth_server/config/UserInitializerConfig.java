package com.shiva.auth_server.config;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.shiva.auth_server.model.User;
import com.shiva.auth_server.repository.UserRepository;

import java.util.Arrays;

@Configuration
public class UserInitializerConfig {

    @Bean
    public CommandLineRunner initializeUsers(
        UserRepository userRepository, 
        PasswordEncoder passwordEncoder
    ) {
        return args -> {
            if (userRepository.count() == 0) {
                User adminUser = new User(
                    "admin", 
                    passwordEncoder.encode("admin123"), 
                    Arrays.asList("ADMIN", "USER")
                );
                User regularUser = new User(
                    "user", 
                    passwordEncoder.encode("user123"), 
                    Arrays.asList("USER")
                );
                userRepository.saveAll(Arrays.asList(adminUser, regularUser));
            }
        };
    }
}