package com.groom.cloudlibrarian.login.jwt;

import com.groom.cloudlibrarian.login.MemberRole;
import com.groom.cloudlibrarian.login.dto.Member;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;

@Slf4j
public class CustomSecurityUserDetails implements UserDetails {
    private final Member member;
    public CustomSecurityUserDetails(Member member) {
        this.member = member;
    }
    // 현재 user의 role을 반환 (ex. "ADMIN" / "USER" 등)
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        log.info("Collection<? extends GrantedAuthority> getAuthorities()");
        Collection<GrantedAuthority> collection = new ArrayList<>();
        collection.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return member.getRole().name();
            }
        });
        return collection;
    }
    public MemberRole getRole() {
        log.info("getRole() - member.role");
        return member.getRole();
    }
    // Security user의 비밀번호 반환 (password로 설정함)
    @Override
    public String getPassword() {
        log.info("getPassword() - member.password");
        return member.getPassword();
    }
    // Security user의 username 반환 (loginId로 설정함)
    @Override
    public String getUsername() {
        log.info("getUsername() - member.loginid()");
        return member.getLoginId();
    }
    @Override
    public boolean isAccountNonExpired() {
        log.info("isAccountNonExpired()");
        return true;
    }
    @Override
    public boolean isAccountNonLocked() {
        log.info("isAccountNonLocked()");
        return true;
    }
    @Override
    public boolean isCredentialsNonExpired() {
        log.info("isCredentialsNonExpired()");
        return true;
    }
    @Override
    public boolean isEnabled() {
        log.info("isEnabled()");
        return true;
    }
}
