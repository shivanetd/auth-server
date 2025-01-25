package com.shiva.auth_server.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.validation.Valid;

import com.shiva.auth_server.dto.UserRegistrationDto;
import com.shiva.auth_server.model.User;
import com.shiva.auth_server.service.UserRegistrationService;

@RestController
@RequestMapping("/api/register")
public class UserRegistrationController {
    
    private final UserRegistrationService registrationService;

    public UserRegistrationController(UserRegistrationService registrationService){
        this.registrationService = registrationService;
    }

    @PostMapping
    public ResponseEntity<?> registerUser(@Valid @RequestBody UserRegistrationDto registrationDto) {
        try {
            User registeredUser = registrationService.registerNewUser(registrationDto);
            return ResponseEntity.ok(registeredUser.getUsername() + " registered successfully");
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
}
