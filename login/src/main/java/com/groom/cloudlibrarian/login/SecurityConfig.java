package com.groom.cloudlibrarian.login;

import com.groom.cloudlibrarian.login.jwt.JWTFilter;
import com.groom.cloudlibrarian.login.jwt.JWTUtil;
import com.groom.cloudlibrarian.login.jwt.LoginFilter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig {
//    // ------------------spring security jwt------------------
//    private final AuthenticationConfiguration configuration;
//    private final JWTUtil jwtUtil;
//    @Bean
//    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
//        return configuration.getAuthenticationManager();
//    }
//    @Bean
//    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
//        // spring security jwt
//        // csrf disable 설정
//        // csrf : 사이트 위변조 방지 설정 (스프링 시큐리티에는 자동으로 설정 되어 있음)
//        // csrf기능 켜져있으면 post 요청을 보낼때 csrf 토큰도 보내줘야 로그인 진행됨 !
//        // 개발단계에서만 csrf 잠시 꺼두기
//        http.csrf((auth) -> auth.disable());
//        // 폼로그인 형식 disable 설정 => POSTMAN으로 검증할 것임!
//        http.formLogin((auth) -> auth.disable());
//        // http basic 인증 방식 disable 설정
//        http.httpBasic((auth -> auth.disable()));
//        // 경로별 인가 작업
//        http.authorizeHttpRequests((auth) -> auth
//                        .requestMatchers("/jwt-login", "/jwt-login/", "/jwt-login/login", "/jwt-login/join").permitAll()
//                        .requestMatchers("/jwt-login/admin").hasAuthority("ADMIN")
//                        .anyRequest().authenticated());
//        // 세션 설정
//        http.sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
//        // 새로 만든 로그인 필터를 원래의 (UsernamePasswordAuthenticationFilter)의 자리에 넣음
//        http.addFilterAt(new LoginFilter(authenticationManager(configuration), jwtUtil), UsernamePasswordAuthenticationFilter.class);
//        // 로그인 필터 이전에 JWTFilter를 넣음
//        http.addFilterBefore(new JWTFilter(jwtUtil), LoginFilter.class);
//        return http.build();
//    }
//    // ------------------spring security jwt end---------------------------------

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        // oauth2 + JWT
        // csrf disable 설정
        // csrf : 사이트 위변조 방지 설정 (스프링 시큐리티에는 자동으로 설정 되어 있음)
        // csrf기능 켜져있으면 post 요청을 보낼때 csrf 토큰도 보내줘야 로그인 진행됨 !
        // 개발단계에서만 csrf 잠시 꺼두기
        http.csrf((auth) -> auth.disable());
        // 폼로그인 형식 disable 설정 => POSTMAN으로 검증할 것임!
        http.formLogin((auth) -> auth.disable());
        // http basic 인증 방식 disable 설정
        http.httpBasic((auth -> auth.disable()));
        // 접근 권한 설정
        http.authorizeHttpRequests((auth) -> auth
                .requestMatchers("/oauth2-login/admin", "localhost:3000/admin").hasAuthority(MemberRole.ADMIN.name())   // backend test
                .requestMatchers("/oauth2-login/info", "localhost:3000/info").authenticated() // 로그인만 한다면 모든 사용자가 접근 가능    // backend test
//                .requestMatchers("/jwt-login/admin").hasRole("ADMIN") // 앞에 "ROLE_" 추가해서 일치여부확인
//                .requestMatchers("[도메인]/admin").hasAuthority(MemberRole.ADMIN.name())   // 배포용
//                .requestMatchers("[도메인]/info").authenticated() // 배포용
                .anyRequest().permitAll());
        // 폼 로그인 방식 설정
        http.formLogin((auth) -> auth
                .loginPage("http://localhost:3000/login")
//                .loginProcessingUrl("/oauth2-login/loginProc")
                .loginProcessingUrl("/security-config/form-login/login-processing-url")
                .usernameParameter("loginId")
                .passwordParameter("password")
                .defaultSuccessUrl("/oauth2-login")
                .failureUrl("/oauth2-login/login")
                .failureHandler((request, response, exception)->{
                    log.info("\n\nrequest : {}\nresponse : {}\nexception : {}\n\n", request, response, exception);
                    response.sendRedirect("http://localhost:3000/fail");
                })
                .permitAll());
        // OAuth 2.0 로그인 방식 설정
        http.oauth2Login((auth) -> auth
                .loginPage("http://localhost:3000/login")   // 로컬용
                .defaultSuccessUrl("http://localhost:3000") // 로컬용
                .failureUrl("http://localhost:3000/fail")   // 로컬용
                .failureHandler((request, response, exception)->{   // 로컬용
                    log.info("\n\nrequest : {}\nresponse : {}\nexception : {}\n\n", request, response, exception);
                    response.sendRedirect("http://localhost:3000/fail");
                })
//                .loginPage("[도메인]/login")     // 배포용
//                .defaultSuccessUrl("[도메인]")   // 배포용
//                .failureUrl("[도메인]/fail")     // 배포용
//                .failureHandler((request, response, exception)->{ // 배포용
//                    log.info("\n\nrequest : {}\nresponse : {}\nexception : {}\n\n", request, response, exception);
//                    response.sendRedirect("[도메인]/fail");
//                })
                .permitAll());
        // 로그아웃 URL 설정
        http.logout((auth) -> auth
                .logoutUrl("/oauth2-login/logout")
                .logoutSuccessUrl("/oauth2-login"));
        return http.build();
//        // oauth2
//        // 접근 권한 설정
//        http.authorizeHttpRequests((auth) -> auth
////                .requestMatchers("/oauth2-login/admin").hasAuthority(MemberRole.ADMIN.name())   // backend test
////                .requestMatchers("/oauth2-login/info").authenticated() // 로그인만 한다면 모든 사용자가 접근 가능    // backend test
//                .requestMatchers("/admin").hasAuthority(MemberRole.ADMIN.name())
//                .requestMatchers("/info").authenticated() // 로그인만 한다면 모든 사용자가 접근 가능
//                .anyRequest().permitAll());
//        // 폼 로그인 방식 설정
//        http.formLogin((auth) -> auth
//                .loginPage("http://localhost:3000/login")
////                .loginProcessingUrl("/oauth2-login/loginProc")
//                .loginProcessingUrl("/security-config/form-login/login-processing-url")
//                .usernameParameter("loginId")
//                .passwordParameter("password")
//                .defaultSuccessUrl("/oauth2-login")
//                .failureUrl("/oauth2-login/login")
//                .failureHandler((request, response, exception)->{
//                    log.info("\n\nrequest : {}\nresponse : {}\nexception : {}\n\n", request, response, exception);
//                    response.sendRedirect("http://localhost:3000/fail");
//                })
//                .permitAll());
//        // OAuth 2.0 로그인 방식 설정
//        http.oauth2Login((auth) -> auth
//                .loginPage("http://localhost:3000/login")   // 로컬용
//                .defaultSuccessUrl("http://localhost:3000") // 로컬용
//                .failureUrl("http://localhost:3000/fail")   // 로컬용
//                .failureHandler((request, response, exception)->{   // 로컬용
//                    log.info("\n\nrequest : {}\nresponse : {}\nexception : {}\n\n", request, response, exception);
//                    response.sendRedirect("http://localhost:3000/fail");
//                })
////                .loginPage("[도메인]/login")     // 배포용
////                .defaultSuccessUrl("[도메인]")   // 배포용
////                .failureUrl("[도메인]/fail")     // 배포용
////                .failureHandler((request, response, exception)->{ // 배포용
////                    log.info("\n\nrequest : {}\nresponse : {}\nexception : {}\n\n", request, response, exception);
////                    response.sendRedirect("[도메인]/fail");
////                })
//                .permitAll());
//        // 로그아웃 URL 설정
//        http.logout((auth) -> auth
//                .logoutUrl("/oauth2-login/logout")
//                .logoutSuccessUrl("/oauth2-login"));
//        // csrf : 사이트 위변조 방지 설정 (스프링 시큐리티에는 자동으로 설정 되어 있음)
//        // csrf기능 켜져있으면 post 요청을 보낼때 csrf 토큰도 보내줘야 로그인 진행됨 !
//        // 개발단계에서만 csrf 잠시 꺼두기
//        http.csrf((auth) -> auth.disable());
//        return http.build();
    }
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder(){ return new BCryptPasswordEncoder(); }
}
