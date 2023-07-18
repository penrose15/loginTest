package com.example.loginTest.domain.user.service;

import com.example.loginTest.domain.user.dto.UserSignUpDTO;
import com.example.loginTest.domain.user.entity.Member;
import com.example.loginTest.domain.user.mapper.MemberMapper;
import com.example.loginTest.domain.user.repository.MemberRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.NoSuchElementException;

@Transactional
@RequiredArgsConstructor
@Service
public class MemberManagementService {
    private final MemberRepository memberRepository;
    private final MemberMapper memberMapper;

    public Long signUpUser(UserSignUpDTO signUpDTO) {
        Member member = memberMapper.toEntity(signUpDTO);
        member = memberRepository.save(member);

        return member.getId();
    }

    public Member findById(Long id) {
        return memberRepository.findById(id)
                .orElseThrow(() -> new NoSuchElementException("존재하지 않는 유저"));
    }

    public Member findByEmail(String email, RuntimeException e) {
        return memberRepository.findByEmail(email)
                .orElseThrow(() -> e);
    }
}
