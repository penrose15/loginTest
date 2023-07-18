package com.example.loginTest.global.auth.service;

import com.example.loginTest.domain.user.entity.Member;
import com.example.loginTest.domain.user.service.MemberManagementService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.NoSuchElementException;

@RequiredArgsConstructor
@Component
public class CustomUserDetailService implements UserDetailsService {
    private final MemberManagementService userService;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        Member user = userService.findByEmail(email, new NoSuchElementException("존재하지 않는 이메일"));
        return new CustomUserDetails(user.getEmail(), user.getPwd(), user.getRoles());
    }
}
