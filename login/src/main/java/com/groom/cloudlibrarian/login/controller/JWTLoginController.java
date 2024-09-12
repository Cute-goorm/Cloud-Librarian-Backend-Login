package com.groom.cloudlibrarian.login.controller;

import com.groom.cloudlibrarian.login.dto.JoinRequest;
import com.groom.cloudlibrarian.login.dto.LoginRequest;
import com.groom.cloudlibrarian.login.dto.Member;
import com.groom.cloudlibrarian.login.MemberService;
import com.groom.cloudlibrarian.login.jwt.JWTUtil;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.util.Collection;
import java.util.Iterator;

// postman으로 test할것
@RestController // (class)@Controller + (method)@ResponseBody > Json 형태로 객체 데이터를 반환
@RequiredArgsConstructor
@RequestMapping("/jwt-login")
@Slf4j
public class JWTLoginController {
    private final MemberService memberService;
    private final JWTUtil jwtUtil;

    private void setModelAttribute(Model model) {
        model.addAttribute("loginType", "jwt-login");
        model.addAttribute("loginCheck", "login");
        model.addAttribute("pageName", "스프링 시큐리티 JWT 로그인");
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
    // postman - body: form-data, {loginId, password, passwordCheck, name}
    @PostMapping("/join")
    public String join(@Valid @ModelAttribute JoinRequest joinRequest, BindingResult bindingResult, Model model) {
        setModelAttribute(model);
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
        return "redirect:/jwt-login";
    }
    // postman - body: raw, {"loginId": "[id]", "password": "[pw]"}
    @PostMapping("/login")
    public String login(@RequestBody LoginRequest loginRequest){
        log.info("{}, {}", loginRequest.getLoginId(), loginRequest.getPassword());
        Member member = memberService.login(loginRequest);
        if(member==null){
            return "ID 또는 비밀번호가 일치하지 않습니다!";
        }
        String token = jwtUtil.createAccessToken(member.getLoginId(), member.getRole().name(), 1000 * 60 * 60L);
        return token;
    }
    // postman - Headers: {Authorization: Bearer [login 시 받은 jwt토큰]}
    @GetMapping("/info")
    public String memberInfo(Authentication auth, Model model) {
        Member loginMember = memberService.getLoginMemberByLoginId(auth.getName());
        return "ID : " + loginMember.getLoginId() + "\n이름 : " + loginMember.getNickname() + "\nrole : " + loginMember.getRole();
    }
    // postman - Headers: {Authorization: Bearer [login 시 받은 jwt토큰]}
    @GetMapping("/admin")
    public String adminPage(Model model) {
        return "인가 성공!";
    }
}
