package com.mettler.jwt.mettlerAuth.Security.jwt;

import java.time.Duration;
import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import org.springframework.web.util.WebUtils;

import com.mettler.jwt.mettlerAuth.Security.services.UserDetailsImpl;

import io.jsonwebtoken.*;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;

@Component
public class JwtUtils {
  private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

  @Value("${mettler.app.jwtSecret}")
  private String jwtSecret;

  @Value("${mettler.app.jwtExpirationMs}")
  private long jwtExpirationMs;

  @Value("${mettler.app.jwtCookieName}")
  private String jwtCookie;

  public String getJwtFromCookies(HttpServletRequest request) {
    Cookie cookie = WebUtils.getCookie(request, jwtCookie);
    if (cookie != null) {
      return cookie.getValue();
    } else {
      return null;
    }
  }

  public ResponseCookie generateJwtCookie(UserDetailsImpl userPrincipal) {
    String jwt = generateTokenFromUsername(userPrincipal.getUsername());
    ResponseCookie cookie = ResponseCookie.from(jwtCookie, jwt)
        .path("/")
        .maxAge(Duration.ofSeconds(1 * 60 * 60))
        .httpOnly(true)
        .secure(false)
        .sameSite("None")
        .build();
    return cookie;
  }

  public ResponseCookie getCleanJwtCookie() {
    ResponseCookie cookie = ResponseCookie.from(jwtCookie, null)
        .path("/")
        .maxAge(Duration.ofSeconds(0))
        .httpOnly(true)
        .secure(false)
        .sameSite("None")
        .build();
    return cookie;
  }

  public String getUserNameFromJwtToken(String token) {
    return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
  }

  public boolean validateJwtToken(String authToken) {
    try {
      Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
      return true;
    } catch (SignatureException e) {
      logger.error("Invalid JWT signature: {}", e.getMessage());
    } catch (MalformedJwtException e) {
      logger.error("Invalid JWT token: {}", e.getMessage());
    } catch (ExpiredJwtException e) {
      logger.error("JWT token is expired: {}", e.getMessage());
    } catch (UnsupportedJwtException e) {
      logger.error("JWT token is unsupported: {}", e.getMessage());
    } catch (IllegalArgumentException e) {
      logger.error("JWT claims string is empty: {}", e.getMessage());
    }

    return false;
  }
  
  public String generateTokenFromUsername(String username) {   
    return Jwts.builder()
        .setSubject(username)
        .setIssuedAt(new Date())
        .setExpiration(new Date(System.currentTimeMillis() + jwtExpirationMs))
        .signWith(SignatureAlgorithm.HS512, jwtSecret)
        .compact();
  }

public long getJwtExpirationMs() {
	
	return jwtExpirationMs;
}
}
