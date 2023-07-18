package com.example.loginTest.domain.user.mapper;

import com.example.loginTest.domain.user.dto.UserSignUpDTO;
import com.example.loginTest.domain.user.entity.Roles;
import com.example.loginTest.domain.user.entity.Users;
import org.springframework.stereotype.Component;

@Component
public class UserMapper {
    public Users toEntity(UserSignUpDTO dto) {
        return Users.builder()
                .name(dto.getName())
                .email(dto.getEmail())
                .password(dto.getPassword())
                .roles(Roles.USER)
                .build();
    }
}
