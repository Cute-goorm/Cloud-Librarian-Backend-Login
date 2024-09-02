package com.groom.cloudlibrarian.login.oauth2.google;

import com.groom.cloudlibrarian.login.oauth2.OAuth2UserInfo;
import lombok.AllArgsConstructor;

import java.util.Map;

@AllArgsConstructor
public class GoogleUserDetails implements OAuth2UserInfo {
    private Map<String, Object> attributes;
    @Override
    public String getProvider() {
        return "google";
    }
    @Override
    public String getProviderId() {
        return (String) attributes.get("sub");
    }
    @Override
    public String getEmail() {
        return (String) attributes.get("email");
    }
    @Override
    public String getName() {
        return (String) attributes.get("name");
    }
}
