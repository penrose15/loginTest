package com.example.loginTest.global.auth.filter;

import com.example.loginTest.domain.user.entity.Users;
import com.example.loginTest.domain.user.service.UserManagementService;
import com.example.loginTest.global.auth.dto.LoginDTO;
import com.example.loginTest.global.auth.jwt.JwtTokenizer;
import com.example.loginTest.global.auth.refreshtoken.RefreshToken;
import com.example.loginTest.global.auth.service.CustomUserDetails;
import com.example.loginTest.global.redis.RedisTemplateRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.NoSuchElementException;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;
    private final RedisTemplateRepository redisTemplateRepository;
    private final JwtTokenizer jwtTokenizer;
    private final PasswordEncoder passwordEncoder;
    private final UserManagementService userManagementService;

    @SneakyThrows
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        ObjectMapper objectMapper = new ObjectMapper();
        LoginDTO loginDTO = objectMapper.readValue(request.getInputStream(), LoginDTO.class);

        Users users;
        try {
            users = userManagementService.findByEmail(loginDTO.getUsername());
        } catch (NoSuchElementException e) {
            throw new AuthenticationException("email not found") {
                @Override
                public String getMessage() {
                    return super.getMessage();
                }
            };
        }

        if(!passwordEncoder.matches(loginDTO.getPassword(), users.getPassword())) {
            throw new AuthenticationException("wrong password") {
                @Override
                public String getMessage() {
                    return super.getMessage();
                }
            };
        }

        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginDTO.getUsername(), loginDTO.getPassword());

        return authenticationManager.authenticate(authenticationToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        CustomUserDetails customUserDetails = (CustomUserDetails) authResult.getPrincipal();
        String accessToken = delegateAccessToken(customUserDetails);
        String refreshToken = delegateRefreshToken(customUserDetails);

        response.setHeader("Authorization","Bearer "+ accessToken);
        response.setHeader("Refresh", "Bearer "+ refreshToken);

        redisTemplateRepository.save(new RefreshToken("Bearer" + refreshToken, customUserDetails.getEmail()));

        this.getSuccessHandler().onAuthenticationSuccess(request, response, authResult);
    }

    private String delegateAccessToken(CustomUserDetails customUserDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("username", customUserDetails.getEmail());
        claims.put("roles",customUserDetails.getRole().name());

        String subject = customUserDetails.getEmail();
        Date expiration = jwtTokenizer.getTokenExpiration(Integer.parseInt(jwtTokenizer.getAccessTokenExpirationMinutes()));
        String base64EncodedSecretKey = jwtTokenizer.encodeBase64SecretKey(jwtTokenizer.getSecretKey());
        String accessToken = jwtTokenizer.generateAccessToken(claims, subject, expiration, base64EncodedSecretKey);
        return accessToken;
    }

    private String delegateRefreshToken(CustomUserDetails customUserDetails) {
        String subject = customUserDetails.getEmail();
        Date expiration = jwtTokenizer.getTokenExpiration(Integer.parseInt(jwtTokenizer.getRefreshTokenExpirationMinutes()));
        String base64EncodedSecretKey = jwtTokenizer.encodeBase64SecretKey(jwtTokenizer.getSecretKey());

        String refreshToken = jwtTokenizer.generateRefreshToken(subject, expiration, base64EncodedSecretKey);
        return refreshToken;
    }
}
