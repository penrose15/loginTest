package com.example.loginTest.domain.user.service;

import com.example.loginTest.domain.user.dto.UserSignUpDTO;
import com.example.loginTest.domain.user.entity.Users;
import com.example.loginTest.domain.user.mapper.UserMapper;
import com.example.loginTest.domain.user.repository.UsersRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.NoSuchElementException;

@Transactional
@RequiredArgsConstructor
@Service
public class UserManagementService {
    private final UsersRepository usersRepository;
    private final UserMapper userMapper;

    public Long signUpUser(UserSignUpDTO signUpDTO) {
        Users users = userMapper.toEntity(signUpDTO);
        users = usersRepository.save(users);

        return users.getId();
    }

    public Users findById(Long id) {
        return usersRepository.findById(id)
                .orElseThrow(() -> new NoSuchElementException("존재하지 않는 유저"));
    }

    public Users findByEmail(String email) {
        return usersRepository.findByEmail(email)
                .orElseThrow(() -> new NoSuchElementException("존재하지 않는 유저"));
    }
}
