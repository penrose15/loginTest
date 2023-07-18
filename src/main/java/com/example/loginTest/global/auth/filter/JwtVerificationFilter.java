package com.example.loginTest.global.auth.filter;

import com.example.loginTest.domain.user.entity.Member;
import com.example.loginTest.domain.user.service.MemberManagementService;
import com.example.loginTest.global.auth.jwt.JwtTokenizer;
import com.example.loginTest.global.auth.service.CustomUserDetails;
import com.example.loginTest.global.redis.RedisTemplateRepository;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.*;

@Slf4j
@RequiredArgsConstructor
public class JwtVerificationFilter extends OncePerRequestFilter {
    private final JwtTokenizer jwtTokenizer;
    private final MemberManagementService userService;
    private final RedisTemplateRepository redisTemplateRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            Map<String, Object> claims = verifyJws(request);
            setAuthenticationToContext(claims);
        }  catch (ExpiredJwtException ee) {
            ee.printStackTrace();
            reissueToken(request, response);
        } catch (Exception e) {
            e.printStackTrace();
            request.setAttribute("exception", e);
        }

        filterChain.doFilter(request,response);
    }
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String authorization = request.getHeader("Authorization");
        return authorization == null || !authorization.startsWith("Bearer ");
    }

    private String getAccessJwtToken(HttpServletRequest request) {
        if(request.getHeader("Authorization") != null) {
            return request.getHeader("Authorization").substring(7);
        }
        return null;
    }
    private String getRefreshToken(HttpServletRequest request) {
        if(request.getHeader("Refresh") != null) {
            return request.getHeader("Refresh");
        }
        return null;
    }

    private Map<String, Object> verifyJws(HttpServletRequest request) {
        String jws = request.getHeader("Authorization").replace("Bearer ", ""); // (3-1)
        String base64EncodedSecretKey = jwtTokenizer.encodeBase64SecretKey(jwtTokenizer.getSecretKey()); // (3-2)
        Map<String, Object> claims = jwtTokenizer.getClaims(jws, base64EncodedSecretKey).getBody();   // (3-3)

        return claims;
    }

    private void reissueToken(HttpServletRequest request, HttpServletResponse response) {
        log.info(">> start reissue token");
        String jws = getAccessJwtToken(request);
        String refreshToken = getRefreshToken(request);

        if(!jwtTokenizer.validateToken(jws) && refreshToken != null) {
            try {
                refreshToken = refreshToken.substring(7);
                if(jwtTokenizer.validateToken(refreshToken)) {
                    String email = jwtTokenizer.getEmailFromRefreshToken(refreshToken);

                    String email2 = redisTemplateRepository.findById(email)
                            .orElseThrow(NoSuchElementException::new)
                            .getEmail();

                    Member member = userService.findByEmail(email2, new NoSuchElementException("잘못된 토큰"));

                    if(email.equals(member.getEmail())) {
                        Map<String, Object> claims = new HashMap<>();
                        claims.put("username", member.getEmail());
                        claims.put("roles", member.getRoles());
                        System.out.println(">>");
                        Date expiration = jwtTokenizer.getTokenExpiration(Integer.parseInt(jwtTokenizer.getAccessTokenExpirationMinutes()));
                        String base64EncodedSecretKey = jwtTokenizer.encodeBase64SecretKey(jwtTokenizer.getSecretKey());
                        String accessToken = jwtTokenizer.generateAccessToken(claims, email, expiration, base64EncodedSecretKey);
                        response.setHeader("Authorization", accessToken);
                        setAuthenticationToContext(claims);
                    }
                    else {
                        throw new MalformedJwtException("wrong refreshToken");
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            log.info("리프레시 토큰 없음, 유효하지 않은 엑서스 토큰");
        }
    }

    private void setAuthenticationToContext(Map<String, Object> claims) {
        String username = (String) claims.get("username");

        Member member = userService.findByEmail(username, new NoSuchElementException("존재하지 않는 유저"));

        CustomUserDetails customUserDetails = new CustomUserDetails(member.getEmail(), member.getPwd(), member.getRoles());

        List<GrantedAuthority> authorities = new ArrayList<>();
        String roles = (String) claims.get("roles");
        authorities.add(new SimpleGrantedAuthority("ROLE_" + roles));

        Authentication authentication = new UsernamePasswordAuthenticationToken(customUserDetails, null, authorities);
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}
