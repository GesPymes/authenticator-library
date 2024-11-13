package com.gespyme.authenticator.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

public class TokenExtractor {

  /*
  @Value("{jwt.token.validity}") // 60 * 60
  private final int tokenValidity;

  @Value("{jwt.secret.key}") // 60 * 60
  private final String secretKey;
  */

    private static final String password = "GesPyme.uoc.SecureKey.2024!2025__!";

    public static String getSubject(String token) {
        Claims claims = extractClaim(token);
        return claims.getSubject();
    }

    public static String getRole(String token) {
        Claims claims = extractClaim(token);
        return claims.get("role", String.class);
    }

    public static Date getExpirationDate(String token) {
        Claims claims = extractClaim(token);
        return claims.getExpiration();
    }

    public static boolean isTokenExpired(String token) {
        return getExpirationDate(token).before(new Date());
    }

    private static Claims extractClaim(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (Exception e) {
            // throw new UnauthorizedException("Invalid token", e);
            throw new RuntimeException(e);
        }
    }

    private static SecretKey getSigningKey() {
        byte[] keyBytes = password.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
