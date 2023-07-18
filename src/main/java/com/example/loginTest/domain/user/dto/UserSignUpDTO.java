package com.example.loginTest.domain.user.dto;

import com.example.loginTest.domain.user.entity.Users;
import lombok.Getter;

@Getter
public class UserSignUpDTO {
    private String name;
    private String email;
    private String password;

}
