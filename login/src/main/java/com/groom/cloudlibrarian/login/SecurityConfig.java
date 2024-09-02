package com.groom.cloudlibrarian.login;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

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
//                        .requestMatchers("/jwt-login/admin").hasRole("ADMIN")
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
        // oauth2
        // 접근 권한 설정
        http.authorizeHttpRequests((auth) -> auth
                .requestMatchers("/oauth2-login/admin").hasAuthority(MemberRole.ADMIN.name())
                .requestMatchers("/oauth2-login/info").authenticated() // 로그인만 한다면 모든 사용자가 접근 가능
                .anyRequest().permitAll());
        // 폼 로그인 방식 설정
        http.formLogin((auth) -> auth.loginPage("/oauth2-login/login")
                .loginProcessingUrl("/oauth2-login/loginProc")
                .usernameParameter("loginId")
                .passwordParameter("password")
                .defaultSuccessUrl("/oauth2-login")
                .failureUrl("/oauth2-login/login")
                .permitAll());
        // OAuth 2.0 로그인 방식 설정
        http.oauth2Login((auth) -> auth.loginPage("/oauth2-login/login")
                .defaultSuccessUrl("/oauth2-login")
                .failureUrl("/oauth2-login/login")
                .permitAll());
        // 로그아웃 URL 설정
        http.logout((auth) -> auth
                .logoutUrl("/oauth2-login/logout")
                .logoutSuccessUrl("/oauth2-login"));
        // csrf : 사이트 위변조 방지 설정 (스프링 시큐리티에는 자동으로 설정 되어 있음)
        // csrf기능 켜져있으면 post 요청을 보낼때 csrf 토큰도 보내줘야 로그인 진행됨 !
        // 개발단계에서만 csrf 잠시 꺼두기
        http.csrf((auth) -> auth.disable());
        return http.build();
    }
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder(){ return new BCryptPasswordEncoder(); }
}
