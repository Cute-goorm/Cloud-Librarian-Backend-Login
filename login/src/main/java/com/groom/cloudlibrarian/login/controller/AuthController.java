package com.groom.cloudlibrarian.login.controller;

import com.groom.cloudlibrarian.login.MemberService;
import com.groom.cloudlibrarian.login.WebConfig;
import com.groom.cloudlibrarian.login.dto.JoinRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

@Controller
@RequiredArgsConstructor
@RequestMapping("/api/auth")
@Slf4j
public class AuthController {
    private final String domain = WebConfig.domain;
    private final MemberService memberService;
    @GetMapping("/login/oauth")
    public String oauthLogin(String provider) {
        String redirect = "redirect:/oauth2/authorization" + provider;
        log.info("GET - /api/auth/login/oauth2/oauth - {} login\nredirect : {}", provider, redirect);
        return redirect;
    }
    @GetMapping("login/kakao")
    public String kakaoLogin() {
        String redirect = "redirect:/oauth2/authorization/kakao";
        log.info("GET - /api/auth/login/oauth2/kakao - kakao login\nredirect : {}", redirect);
        return redirect;
    }
    @GetMapping("login/google")
    public String googleLogin() {
        String redirect = "redirect:/oauth2/authorization/google";
        log.info("GET - /api/auth/login/oauth2/google - google login\nredirect : {}", redirect);
        return redirect;
    }
    @GetMapping("/signup")
    public String joinPage() {
        log.info("GET - /api/auth/signup");
        String redirect = "redirect:" + domain + "/signup";
        return redirect;
    }
    @PostMapping("/signup")
    public String join(@Valid @ModelAttribute JoinRequest joinRequest, BindingResult bindingResult, Model model) {
        log.info("POST - /api/auth/signup");
        // ID 중복 여부 확인
        if (memberService.checkLoginIdDuplicate(joinRequest.getLoginId())) {
            return "ID가 존재합니다.";
        }
        // 비밀번호 = 비밀번호 체크 여부 확인
        if (!joinRequest.getPassword().equals(joinRequest.getPasswordCheck())) {
            return "비밀번호가 일치하지 않습니다.";
        }
        // 에러가 존재하지 않을 시 joinRequest 통해서 회원가입 완료
        memberService.securityJoin(joinRequest);
        // 회원가입 시 홈 화면으로 이동
        return "redirect:" + domain + "/home";
    }
}
