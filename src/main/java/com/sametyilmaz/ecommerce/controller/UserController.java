package com.sametyilmaz.ecommerce.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/users")
public class UserController {
    @GetMapping("/profile")
    public ResponseEntity<String> getProfile(Authentication auth) {
        return ResponseEntity.ok("Hello, " + auth.getName());
    }
}
