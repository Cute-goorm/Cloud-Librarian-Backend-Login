package com.groom.cloudlibrarian.login.oauth2.kakao;

import com.groom.cloudlibrarian.login.oauth2.OAuth2UserInfo;
import lombok.AllArgsConstructor;

import java.util.Map;

@AllArgsConstructor
public class KakaoUserDetails implements OAuth2UserInfo {
    private Map<String, Object> attributes;
    @Override
    public String getProvider() { return "kakao"; }
    @Override
    public String getProviderId() { return attributes.get("id").toString(); }
    @Override
    public String getEmail() {
        // [kakao developer 왼쪽 탭 > 제품설정 > 카카오로그인 > 동의항목 > 카카오계정(이메일) 권한필요 (개인정보 동의항목심사신청 > 비즈앱 전환) ]
//        return (String) ((Map) attributes.get("kakao_account")).get("email");
        return "test@test.com";
    }
    @Override
    public String getName() { return (String) ((Map) attributes.get("properties")).get("nickname"); }
}
