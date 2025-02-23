package com.example.zerotrustframework.authentication;

import com.example.zerotrustframework.common.User;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.*;

@Component
public class TokenValidator {
    @Value("${zero-trust.auth.secretKey:}")
    private String privateKeyBase64;

    @Value("${zero-trust.auth.issuer:}")
    private String expectedIssuer;

    @Value("${zero-trust.auth.audience:}")
    private String expectedAudience;

    @Value("${application.security.jwt.expiration}")
    private long expiration;

    private static Key hmacKey;

    public void initKey() {
        if (privateKeyBase64 != null && !privateKeyBase64.isEmpty()) {
            byte[] decodedKey = Base64.getDecoder().decode(privateKeyBase64);
            this.hmacKey = Keys.hmacShaKeyFor(decodedKey);

        } else {
            //Log error with dedicated module!!!
            System.err.println("Warning: No secret key was provided");
        }
    }

    public boolean isValid(String token, User user) {
        try {
            Jws<Claims> jws = Jwts.parserBuilder()
                    .setSigningKey(hmacKey)
                    .requireIssuer(expectedIssuer)
                    .build()
                    .parseClaimsJws(token);

            Claims body = jws.getBody();
            if (expectedAudience != null && !expectedAudience.isEmpty()) {
                String aud = body.getAudience();
                if (!expectedAudience.equals(aud)) {
                    return false;
                }
            }
            return true;
        } catch (SecurityException | MalformedJwtException e) {
            // Log exception with dedicated module
            return false;
        } catch (ExpiredJwtException | UnsupportedJwtException | IllegalArgumentException e) {
            //log exc
            return false;
        }
    }

    public String generateToken(User user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("id", user.getId());
        claims.put("username", user.getUsername());
        claims.put("email", user.getEmail());
        claims.put("roles", user.getAuthorities());
        return createToken(claims, user.getUsername());
    }
    public Authentication buildAuthentication(String token) {
        Jws<Claims> jws = Jwts.parserBuilder()
                .setSigningKey(hmacKey)
                .build()
                .parseClaimsJws(token);
        Claims claims = jws.getBody();
        String username = claims.getSubject();

        List<String> roles = claims.get("roles", List.class);
        if (roles == null) {
            roles = Collections.emptyList();
        }

        List<SimpleGrantedAuthority> authorities = roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()))
                .toList();

        return new UsernamePasswordAuthenticationToken(username, null, authorities);
    }

    private String createToken(Map<String, Object> claims, String username) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(hmacKey, SignatureAlgorithm.HS256)
                .compact();
    }

    public static String extractUsername(String token) {
        return getClaims(token).getSubject(); // "sub" claim = username
    }

    private static Claims getClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(hmacKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
