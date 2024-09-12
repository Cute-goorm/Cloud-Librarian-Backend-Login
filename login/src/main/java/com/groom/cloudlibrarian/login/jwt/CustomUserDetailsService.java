package com.groom.cloudlibrarian.login.jwt;

import com.groom.cloudlibrarian.login.MemberRepository;
import com.groom.cloudlibrarian.login.dto.Member;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class CustomUserDetailsService implements UserDetailsService {
    private final MemberRepository memberRepository;
    @Override
    public UserDetails loadUserByUsername(String loginId) throws UsernameNotFoundException {
        log.info("loadUserByUsername username : {}", loginId);
        Member member = memberRepository.findByLoginId(loginId);
        if(member != null) {
            return new CustomSecurityUserDetails(member);
        }
        return null;
    }
}