package com.mettler.jwt.mettlerAuth.Controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.mettler.jwt.mettlerAuth.Security.jwt.JwtUtils;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;

@CrossOrigin
@RestController
@RequestMapping("/api")
public class TestController {

    @Autowired
    private JwtUtils jwtUtils;

    @GetMapping("/CheckAuth")
    public ResponseEntity<?> checkAuth(HttpServletRequest request) {
        String authToken = jwtUtils.getJwtFromCookies(request);
        if (authToken != null && jwtUtils.validateJwtToken(authToken)) {
            return ResponseEntity.ok("Welcome to Mettler Health Care....");
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("JWT token expired");
        }
    }
}
