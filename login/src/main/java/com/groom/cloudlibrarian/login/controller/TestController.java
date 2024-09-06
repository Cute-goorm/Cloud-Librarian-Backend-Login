package com.groom.cloudlibrarian.login.controller;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequiredArgsConstructor
@RequestMapping("/api/login")
@Slf4j
public class TestController {
    @GetMapping
    public String oauthLogin(String provider) {
        String redirect = "redirect:/oauth2/authorization" + provider;
        log.info("{} login, {}", provider, redirect);
        return redirect;
    }
    @GetMapping("/test")
    public String test(HttpServletResponse response) {
        String redirect = "redirect:/localhost:3000";
        log.info("test");
        return redirect;
    }
}
