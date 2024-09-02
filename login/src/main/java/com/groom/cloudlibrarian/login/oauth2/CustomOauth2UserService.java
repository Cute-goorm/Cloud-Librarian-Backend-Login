package com.groom.cloudlibrarian.login.oauth2;

import com.groom.cloudlibrarian.login.dto.Member;
import com.groom.cloudlibrarian.login.MemberRepository;
import com.groom.cloudlibrarian.login.MemberRole;
import com.groom.cloudlibrarian.login.oauth2.facebook.FacebookUserDetails;
import com.groom.cloudlibrarian.login.oauth2.google.GoogleUserDetails;
import com.groom.cloudlibrarian.login.oauth2.kakao.KakaoUserDetails;
import com.groom.cloudlibrarian.login.oauth2.naver.NaverUserDetails;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class CustomOauth2UserService extends DefaultOAuth2UserService {

    private final MemberRepository memberRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);
        log.info("getAttributes : {}",oAuth2User.getAttributes());
        String provider = userRequest.getClientRegistration().getRegistrationId();
        OAuth2UserInfo oAuth2UserInfo = null;
        // 소셜 서비스 로그인 구분
        switch(provider){
            case "google":
                log.info("구글 로그인");
                oAuth2UserInfo = new GoogleUserDetails(oAuth2User.getAttributes());
                break;
            case "kakao":
                log.info("카카오 로그인");
                oAuth2UserInfo = new KakaoUserDetails(oAuth2User.getAttributes());
                break;
            case "naver":
                log.info("네이버 로그인");
                oAuth2UserInfo = new NaverUserDetails(oAuth2User.getAttributes());
                break;
            case "facebook":
                log.info("페이스북 로그인");
                oAuth2UserInfo = new FacebookUserDetails(oAuth2User.getAttributes());
                break;
        }
        String providerId = oAuth2UserInfo.getProviderId();
        String email = oAuth2UserInfo.getEmail();
        String loginId = provider + "_" + providerId;
        String name = oAuth2UserInfo.getName();
        Member findMember = memberRepository.findByLoginId(loginId);
        Member member;
        if (findMember == null) {
            member = Member.builder()
                    .loginId(loginId)
                    .nickname(name)
                    .provider(provider)
                    .providerId(providerId)
                    .role(MemberRole.USER)
                    .build();
            memberRepository.save(member);
        } else{
            member = findMember;
        }
        return new CustomOauth2UserDetails(member, oAuth2User.getAttributes());
    }
}