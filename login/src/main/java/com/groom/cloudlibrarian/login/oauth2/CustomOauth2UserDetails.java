package com.groom.cloudlibrarian.login.oauth2;

import com.groom.cloudlibrarian.login.MemberRole;
import com.groom.cloudlibrarian.login.dto.Member;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

@Slf4j
public class CustomOauth2UserDetails implements UserDetails, OAuth2User {
    private final Member member;
    private Map<String, Object> attributes;
    public CustomOauth2UserDetails(Member member, Map<String, Object> attributes) {
        this.member = member;
        this.attributes = attributes;
    }
    @Override
    public Map<String, Object> getAttributes() {
        log.info("getAttributes()");
        return attributes;
    }

    @Override
    public String getName() {
        log.info("getName()");
        return null;
    }

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
    public MemberRole getRole(){
        log.info("getRole() - member.role");
        return member.getRole();
    }
    @Override
    public String getPassword() {
        log.info("getPassword() - member.password");
        return member.getPassword();
    }
    @Override
    public String getUsername() {
        log.info("getUsername() - member.loginId");
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
