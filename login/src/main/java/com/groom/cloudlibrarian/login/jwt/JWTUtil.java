package com.groom.cloudlibrarian.login.jwt;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

//secret key 를 생성자 주입 방식으로 주입
@Component
public class JWTUtil {
    private SecretKey secretKey;
    private final Long AT_EXPIRED_MS = 60*60*1000L;     // 1H
    private final Long RT_EXPIRED_MS = 24*60*60*1000L;  // 24H

    // @Value : application.yml에서 특정한 변수 데이터를 가져올 수 있음
    // string key는 jwt에서 사용 안하므로 객체 키 생성!
    // "${spring.jwt.secret}" : application.yml에 저장된 spring: jwt: secret 에 저장된 암호화 키 사용
    public JWTUtil(@Value("${spring.jwt.secret}") String secret) {
        this.secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }
    // loginId 반환
    public String getLoginId(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("loginId", String.class);
    }
    // role 반환
    public String getRole(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("role", String.class);
    }
    // 토큰 만료 검증
    public Boolean isExpired(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration().before(new Date());
    }
    // 토큰 생성
    public String createAccessToken(String loginId, String role) {
        return Jwts.builder()
                .claim("loginId", loginId)
                .claim("role", role)
                .issuedAt(new Date(System.currentTimeMillis()))                 // 현재 발행시간 설정
                .expiration(new Date(System.currentTimeMillis() + AT_EXPIRED_MS))   // 만료시간 설정
                .signWith(secretKey)    // 암호화
                .compact();             // 토큰생성
    }
    public String createRefreshToken() {
        return Jwts.builder()
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + RT_EXPIRED_MS))
                .signWith(secretKey)
                .compact();
    }
}
