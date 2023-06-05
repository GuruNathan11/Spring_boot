package com.mettler.jwt.mettlerAuth.Controller;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.mettler.jwt.mettlerAuth.Models.ERole;
import com.mettler.jwt.mettlerAuth.Models.Role;
import com.mettler.jwt.mettlerAuth.Models.Session;
import com.mettler.jwt.mettlerAuth.Models.User;
import com.mettler.jwt.mettlerAuth.Security.jwt.JwtUtils;
import com.mettler.jwt.mettlerAuth.Security.services.UserDetailsImpl;
import com.mettler.jwt.mettlerAuth.repository.RoleRepository;
import com.mettler.jwt.mettlerAuth.repository.SessionRepository;
import com.mettler.jwt.mettlerAuth.repository.UserRepository;
import com.mettler.jwt.mettlerAuth.request.LoginRequest;
import com.mettler.jwt.mettlerAuth.request.SignupRequest;
import com.mettler.jwt.mettlerAuth.response.MessageResponse;
import com.mettler.jwt.mettlerAuth.response.UserResponse;

import jakarta.validation.Valid;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
  @Autowired
  AuthenticationManager authenticationManager;
  
  @Autowired
  private SessionRepository sessionRepository;
  
  @Autowired
  UserRepository userRepository;

  @Autowired
  RoleRepository roleRepository;

  @Autowired
  PasswordEncoder encoder;

  @Autowired
  JwtUtils jwtUtils;
  
  @PostMapping("/createNewRole")
  public ResponseEntity<String> createNewRole(@RequestBody Role role) {
      if (roleRepository.findByName(role.getName()).isPresent()) {
          return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Role already exists: " + role.getName());
      }

      Role createdRole = roleRepository.save(role);
      if (createdRole != null) {
          return ResponseEntity.ok("Role created successfully");
      } else {
          return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to create role");
      }
  }


  @PostMapping("/signin")
  public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

    Authentication authentication = authenticationManager
        .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
    
    Session session = new Session();
    session.setUsername(loginRequest.getUsername());
    session.setSessionId(UUID.randomUUID().toString());
    session.setCreatedDate(LocalDateTime.now());
    Date jwtExpiration = new Date(System.currentTimeMillis() + jwtUtils.getJwtExpirationMs());
    LocalDateTime expireTime = LocalDateTime.ofInstant(jwtExpiration.toInstant(), ZoneId.systemDefault());
    session.setExpireTime(expireTime);
    sessionRepository.save(session);

    SecurityContextHolder.getContext().setAuthentication(authentication);

    UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

    ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(userDetails);

    List<String> roles = userDetails.getAuthorities().stream()
        .map(item -> item.getAuthority())
        .collect(Collectors.toList());

    return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
        .body(new UserResponse(userDetails.getId(),
                                   userDetails.getUsername(),
                                   userDetails.getEmail(),
                                   roles));
  }

  @PostMapping("/signup")
  public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
    if (userRepository.existsByUsername(signUpRequest.getUsername())) {
      return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is already taken!"));
    }

    if (userRepository.existsByEmail(signUpRequest.getEmail())) {
      return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already in use!"));
    }

    // Create new user's account
    User user = new User(signUpRequest.getUsername(),
                         signUpRequest.getEmail(),
                         encoder.encode(signUpRequest.getPassword()));

    Set<String> strRoles = signUpRequest.getRole();
    Set<Role> roles = new HashSet<>();

    if (strRoles == null) {
      Role userRole = roleRepository.findByName(ERole.user)
          .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
      roles.add(userRole);
    } else {
      strRoles.forEach(role -> {
        switch (role) {
        case "admin":
          Role adminRole = roleRepository.findByName(ERole.admin)
              .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
          roles.add(adminRole);

          break;
        case "mod":
          Role modRole = roleRepository.findByName(ERole.moderator)
              .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
          roles.add(modRole);

          break;
        default:
          Role userRole = roleRepository.findByName(ERole.user)
              .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
          roles.add(userRole);
        }
      });
    }

    user.setRoles(roles);
    userRepository.save(user);

    return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
  }


  @PostMapping("/signout")
  public ResponseEntity<?> logoutUser() {
    ResponseCookie cookie = jwtUtils.getCleanJwtCookie();
    return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString())
        .body(new MessageResponse("You've been signed out!"));
  }
}
