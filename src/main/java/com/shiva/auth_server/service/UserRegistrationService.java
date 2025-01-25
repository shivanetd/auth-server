package com.shiva.auth_server.service;

import java.util.Collections;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.shiva.auth_server.dto.UserRegistrationDto;
import com.shiva.auth_server.model.User;
import com.shiva.auth_server.repository.UserRepository;

@Service
public class UserRegistrationService {
     private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserRegistrationService(
        UserRepository userRepository, 
        PasswordEncoder passwordEncoder
    ) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public User registerNewUser(UserRegistrationDto registrationDto) {
        // Check if username already exists
        if (userRepository.findByUsername(registrationDto.getUsername()).isPresent()) {
            throw new RuntimeException("Username already exists");
        }

        // Create new user
        User newUser = new User(
            registrationDto.getUsername(),
            passwordEncoder.encode(registrationDto.getPassword()),
            Collections.singletonList("USER")
        );

        return userRepository.save(newUser);
    }
}
