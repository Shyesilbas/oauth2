package com.serhat.oauth2.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

@Component
public class JwtTokenProvider {

    private final SecretKey SECRET_KEY = Keys.hmacShaKeyFor(Decoders.BASE64.decode("486cbcbfe6c3a2a293d8287f9a77b31813d4bb937530af81e2927911f8e6acf210dd0a9c2cb93166335195d14253313c4afb5b7c36066da2ea441c9805077bf7490ecee53898f54857809fa9ab707afaa6729b3c94233205be5fafa1f940d7b108ead4e46581c736e6d7667476342fc350900171ebcde47cbb2dc99e5cf5d8c15d5242851cbc92d5c21305c52f59ea55fcbe45b616b832ba6a7e27b8d854da4036d25cd68436fad3fa3217b9b5938a6abb9fc6674671da39033e2bddf46373d17abff0ce3739bdc20435ed26e94ad451ff375e6d5210b30985f8e91fe1d57330f37e81a4acb3b6cdb1aa5145911b614fc36bc72c66532b8743ebc65cbdcf5014"));
    private final long EXPIRATION_TIME = 86400000;

    public String createToken(String email) {
        return Jwts.builder()
                .setSubject(email)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(SECRET_KEY)
                .compact();
    }

    public String getEmailFromToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(SECRET_KEY)
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claims.getSubject();
    }
}
