package com.groom.cloudlibrarian.login.controller;

import com.groom.cloudlibrarian.login.MemberService;
import com.groom.cloudlibrarian.login.dto.Member;
import com.groom.cloudlibrarian.login.dto.JoinRequest;
import com.groom.cloudlibrarian.login.dto.LoginRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.*;

import java.util.Collection;
import java.util.Iterator;

@Controller
@RequiredArgsConstructor
@RequestMapping("/oauth2-login")
@Slf4j
public class Oauth2LoginController {
    private final MemberService memberService;
    private void setModelAttribute(Model model) {
        model.addAttribute("loginType", "oauth2-login");
        model.addAttribute("loginCheck", "loginProc");
        model.addAttribute("pageName", "Oauth2 로그인");
    }
    @GetMapping(value = {"", "/"})
    public String home(Model model) {
        setModelAttribute(model);
        String loginId = SecurityContextHolder.getContext().getAuthentication().getName();
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iter = authorities.iterator();
        GrantedAuthority auth = iter.next();
        String role = auth.getAuthority();
        Member loginMember = memberService.getLoginMemberByLoginId(loginId);
        if (loginMember != null) {
            model.addAttribute("nickname", loginMember.getNickname());
        }
        return "home";
    }
    @GetMapping("/join")
    public String joinPage(Model model) {
        setModelAttribute(model);
        // 회원가입을 위해서 model 통해서 joinRequest 전달
        model.addAttribute("joinRequest", new JoinRequest());
        return "join";
    }
    @PostMapping("/join")
    public String join(@Valid @ModelAttribute JoinRequest joinRequest,
                       BindingResult bindingResult, Model model) {
        setModelAttribute(model);
        // ID 중복 여부 확인
        if (memberService.checkLoginIdDuplicate(joinRequest.getLoginId())) {
            bindingResult.addError(new FieldError("joinRequest", "loginId", "ID가 존재합니다."));
        }
        // 비밀번호 = 비밀번호 체크 여부 확인
        if (!joinRequest.getPassword().equals(joinRequest.getPasswordCheck())) {
            bindingResult.addError(new FieldError("joinRequest", "passwordCheck", "비밀번호가 일치하지 않습니다."));
        }
        // 에러가 존재할 시 다시 join.html로 전송
        if (bindingResult.hasErrors()) {
            return "join";
        }
        // 비밀번호 암호화 추가한 회원가입 로직으로 회원가입
        memberService.securityJoin(joinRequest);
        // 회원가입 시 홈 화면으로 이동
        return "redirect:/oauth2-login";
    }
    @GetMapping("/login")
    public String loginPage(Model model) {
        setModelAttribute(model);
        model.addAttribute("loginRequest", new LoginRequest());
        return "login";
    }
    @GetMapping("/info")
    public String memberInfo(Authentication auth, Model model) {
        // 로그인인증X (spring security가 자동으로 로그인 인증)
        setModelAttribute(model);
        Member loginMember = memberService.getLoginMemberByLoginId(auth.getName());
        model.addAttribute("member", loginMember);
        return "info";
    }
    @GetMapping("/admin")
    public String adminPage(Model model) {
        //role 체크X (spring security에서 자동으로 인가)
        setModelAttribute(model);
        return "admin";
    }
}
