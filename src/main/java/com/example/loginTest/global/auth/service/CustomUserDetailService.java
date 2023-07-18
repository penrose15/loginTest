package com.example.loginTest.global.auth.service;

import com.example.loginTest.domain.user.entity.Users;
import com.example.loginTest.domain.user.service.UserManagementService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.NoSuchElementException;

@RequiredArgsConstructor
@Component
public class CustomUserDetailService implements UserDetailsService {
    private final UserManagementService userService;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        try {
            Users user = userService.findByEmail(email);
            return new CustomUserDetails(user.getEmail(), user.getPassword(), user.getRoles());
        } catch (NoSuchElementException e) {
            e.printStackTrace();
            throw e;
        }
    }
}
