package vpunko.musiceventauth.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class JwtTokenService {

//    public String generateToken(String telegramId) {
//
//        String username = "username";
//
//        Map<String, Object> claims = new HashMap<>();
//
//        return Jwts.builder()
//                .claims()
//                .add(claims)
//                .subject(username)
//                .issuedAt(new Date(System.currentTimeMillis()))
//                .expiration(new Date(System.currentTimeMillis() + 60 * 60 * 60))
//                .and()
//                .signWith(getKey())
//                .compact();
//    }

    public String generateToken(Map<String, String> params) {
        String id = params.get("id");
        Map<String, Object> claims = new HashMap<>();
        return Jwts.builder()
                .claims()
                .add(claims)
                .subject(id)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 60 * 60 * 60))
                .and()
                .signWith(getKey())
                .compact();
    }

//    /**
//     * Validate a JWT token and extract claims.
//     */
//    public Claims parseToken(String token) {
//        return Jwts.parser()
//                .setSigningKey(secretKey)
//                .parseClaimsJws(token)
//                .getBody();
//    }

//    /**
//     * Check if the token is valid.
//     */
//    public boolean isValidToken(String token) {
//        try {
//            parseToken(token); // If parsing works, the token is valid
//            return true;
//        } catch (Exception e) {
//            return false;
//        }
//    }

    private Key getKey() {
        KeyGenerator keyGen;
        try {
            keyGen = KeyGenerator.getInstance("HmacSHA256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        SecretKey sk = keyGen.generateKey();
        String secretKey = Base64.getEncoder().encodeToString(sk.getEncoded());
        return Keys.hmacShaKeyFor(secretKey.getBytes());
    }
}
