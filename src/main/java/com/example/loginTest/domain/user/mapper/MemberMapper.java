package com.example.loginTest.domain.user.mapper;

import com.example.loginTest.domain.user.dto.UserSignUpDTO;
import com.example.loginTest.domain.user.entity.Roles;
import com.example.loginTest.domain.user.entity.Member;
import org.springframework.stereotype.Component;

@Component
public class MemberMapper {
    public Member toEntity(UserSignUpDTO dto) {
        return Member.builder()
                .name(dto.getName())
                .email(dto.getEmail())
                .pwd(dto.getPassword())
                .roles(Roles.USER)
                .build();
    }
}
