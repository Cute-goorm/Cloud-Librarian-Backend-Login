package com.groom.cloudlibrarian.login;

import com.groom.cloudlibrarian.login.dto.Member;
import com.groom.cloudlibrarian.login.dto.JoinRequest;
import com.groom.cloudlibrarian.login.dto.LoginRequest;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@Transactional
@RequiredArgsConstructor
@Slf4j
public class MemberService {
    private final MemberRepository memberRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    public boolean checkLoginIdDuplicate(String loginId){
        log.info("checkLoginIdDuplicate() - loginId : {}", loginId);
        return memberRepository.existsByLoginId(loginId);
    }
    public void join(JoinRequest joinRequest) {
        log.info("join() - joinRequest : {}", joinRequest);
        memberRepository.save(joinRequest.toEntity());
    }
    public Member login(LoginRequest loginRequest) {
        log.info("login() - loginRequest : {}", loginRequest);
        Member findMember = memberRepository.findByLoginId(loginRequest.getLoginId());
        if(findMember == null){
            return null;
        }
        if (!(findMember.getPassword().equals(loginRequest.getPassword()) || bCryptPasswordEncoder.matches(loginRequest.getPassword(), findMember.getPassword()))) {
            return null;
        }
        return findMember;
    }
    public Member getLoginMemberById(Long memberId){
        log.info("getLoginMemberById() - memberId : {}", memberId);
        if(memberId == null) return null;
        Optional<Member> findMember = memberRepository.findById(memberId);
        return findMember.orElse(null);
    }
    public Member getLoginMemberByLoginId(String loginId){
        log.info("getLoginMemberByLoginId() - loginId : {}", loginId);
        return memberRepository.findByLoginId(loginId);
    }
    // BCryptPasswordEncoder 를 통해서 비밀번호 암호화 작업 추가한 회원가입 로직
    public void securityJoin(JoinRequest joinRequest){
        log.info("securityJoin() - joinRequest : {}", joinRequest);
        if(memberRepository.existsByLoginId(joinRequest.getLoginId())){
            return;
        }
        joinRequest.setPassword(bCryptPasswordEncoder.encode(joinRequest.getPassword()));
        memberRepository.save(joinRequest.toEntity());
    }
}
