package com.example.loginTest.global.auth.refreshtoken;

import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class RefreshToken {
    @Id
    private String refreshToken;
    private String email;
}
