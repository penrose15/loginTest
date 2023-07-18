package com.example.loginTest.domain.user.entity;

import lombok.Getter;

@Getter
public enum Roles {
    USER("USER"),
    MANAGER("MANAGER"),
    ADMIN("ADMIN");

    private String role;

    Roles(String role) {
        this.role = role;
    }
}
