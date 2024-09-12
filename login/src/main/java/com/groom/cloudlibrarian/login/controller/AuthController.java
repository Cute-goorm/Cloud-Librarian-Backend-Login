package com.groom.cloudlibrarian.login.controller;

import com.groom.cloudlibrarian.login.MemberService;
import com.groom.cloudlibrarian.login.WebConfig;
import com.groom.cloudlibrarian.login.dto.JoinRequest;
import com.groom.cloudlibrarian.login.dto.LoginRequest;
import com.groom.cloudlibrarian.login.dto.Member;
import com.groom.cloudlibrarian.login.jwt.JWTUtil;
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
    private final JWTUtil jwtUtil;
    @GetMapping("/login/oauth")
    public String oauthLogin(String provider) {
        String redirect = "redirect:/oauth2/authorization" + provider;
        log.info("{} login, {}", provider, redirect);
        return redirect;
    }
    @GetMapping("login/kakao")
    public String kakaoLogin() {
        String redirect = "redirect:/oauth2/authorization/kakao";
        log.info("kakao login, {}", redirect);
        return redirect;
    }
    @GetMapping("login/google")
    public String googleLogin() {
        String redirect = "redirect:/oauth2/authorization/google";
        log.info("google login, {}", redirect);
        return redirect;
    }
    @PostMapping("/login")
//    /security-config/form-login/login-processing-url
    public String formLogin(@RequestBody LoginRequest loginRequest){
        log.info("{}, {}", loginRequest.getLoginId(), loginRequest.getPassword());
        Member member = memberService.login(loginRequest);
        if(member==null){
            return "ID 또는 비밀번호가 일치하지 않습니다!";
        }
        String token = jwtUtil.createAccessToken(member.getLoginId(), member.getRole().name(), 1000 * 60 * 60L);
        return token;
    }
    @GetMapping("/signup")
    public String joinPage() {
        log.info("get signup");
        String redirect = "redirect:" + domain + "/signup";
        return redirect;
    }
    @PostMapping("/signup")
    public String join(@Valid @ModelAttribute JoinRequest joinRequest, BindingResult bindingResult, Model model) {
        log.info("post signup");
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
