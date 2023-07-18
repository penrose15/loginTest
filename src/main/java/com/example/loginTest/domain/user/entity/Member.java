package com.example.loginTest.domain.user.entity;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Getter
@Entity
public class Member {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "username", length = 50)
    private String name;
    @Column(name = "email", length = 50)
    private String email;
    @Column(name = "password", length = 50)
    private String pwd;
    @Enumerated(EnumType.STRING)
    private Roles roles;

    @Builder
    public Member(Long id, String name, String email, String pwd, Roles roles) {
        this.id = id;
        this.name = name;
        this.email = email;
        this.pwd = pwd;
        this.roles = roles;
    }
}
