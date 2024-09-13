package com.groom.cloudlibrarian.login;

import com.groom.cloudlibrarian.login.jwt.CustomSecurityUserDetails;
import com.groom.cloudlibrarian.login.jwt.JWTFilter;
import com.groom.cloudlibrarian.login.jwt.JWTUtil;
import com.groom.cloudlibrarian.login.jwt.LoginFilter;
import com.groom.cloudlibrarian.login.oauth2.CustomOauth2UserDetails;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
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
    public String domain = WebConfig.domain;
    private final AuthenticationConfiguration configuration;
    private final JWTUtil jwtUtil;
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }
    private final MemberRepository memberRepository;
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        http.authorizeHttpRequests((auth) -> auth
                .requestMatchers(domain + "/admin").hasAuthority(MemberRole.ADMIN.name())
                .requestMatchers(HttpMethod.PATCH, domain + "/api/books/{book_id}").hasAuthority(MemberRole.ADMIN.name())
                .requestMatchers(HttpMethod.DELETE, domain + "/api/books/{book_id}").hasAuthority(MemberRole.ADMIN.name())
                .requestMatchers(HttpMethod.POST, "/api/books/{book_id}/reviews/**").authenticated() // 로그인만 한다면 모든 사용자가 접근 가능
                .requestMatchers(HttpMethod.PATCH, "/api/books/{book_id}/reviews/**").authenticated() // 로그인만 한다면 모든 사용자가 접근 가능
                .requestMatchers(HttpMethod.DELETE, "/api/books/{book_id}/reviews/**").authenticated() // 로그인만 한다면 모든 사용자가 접근 가능
                .requestMatchers(HttpMethod.PUT, "/api/reviews/**").authenticated() // 로그인만 한다면 모든 사용자가 접근 가능
                .anyRequest().permitAll());
        // 폼 로그인 방식 설정
        http.formLogin((auth) -> auth
                .loginPage(domain + "/login")
                .loginProcessingUrl("/api/auth/login")
                .usernameParameter("loginId")
                .passwordParameter("password")
                .defaultSuccessUrl(domain + "/home")
                .successHandler((request, response, authentication)->{
                    CustomSecurityUserDetails principal = (CustomSecurityUserDetails)authentication.getPrincipal();
                    log.info("formLogin successHandler auth : {}", principal);
                    // AT RT 생성
                    String loginId = principal.getUsername();
                    String memberRole = principal.getRole().name();
                    String accessToken = jwtUtil.createAccessToken(loginId, memberRole);
                    String refreshToken = jwtUtil.createRefreshToken();

                    response.addHeader("Authorization", "Bearer " + accessToken);
                    response.addHeader("RefreshToken", "Bearer " + refreshToken);
//                    response.sendRedirect(domain + "/home");
                })
                .failureUrl("/oauth2-login/login")
                .failureHandler((request, response, authentication)->{
                    log.info("formLogin failureHandler\nrequest : {}\nresponse : {}\nauthentication : {}\n\n", request, response, authentication);
                    response.sendRedirect(domain + "/login");
                })
                .permitAll());
        // OAuth 2.0 로그인 방식 설정
        http.oauth2Login((auth) -> auth
                .loginPage(domain + "/login")
                .defaultSuccessUrl(domain)
                .successHandler((request, response, authentication)->{
                    CustomOauth2UserDetails principal = (CustomOauth2UserDetails)authentication.getPrincipal();
                    log.info("oauth2Login successHandler auth : {}", principal);
                    // AT RT 생성
                    String loginId = principal.getUsername();
                    String memberRole = principal.getRole().name();
                    String accessToken = jwtUtil.createAccessToken(loginId, memberRole);
                    String refreshToken = jwtUtil.createRefreshToken();

                    response.addHeader("Authorization", "Bearer " + accessToken);
                    response.addHeader("RefreshToken", "Bearer " + refreshToken);
//                    response.sendRedirect(domain + "/home");
                })
                .failureUrl(domain + "/fail")
                .failureHandler((request, response, authentication)->{
                    log.info("oauth2Login failureHandler\nrequest : {}\nresponse : {}\nexception : {}\n\n", request, response, authentication);
                    response.sendRedirect(domain + "/login");
                })
                .permitAll());
        // 로그아웃 URL 설정
        http.logout((auth) -> auth
                .logoutUrl("/api/auth/logout")
                .logoutSuccessUrl(domain));
        // csrf : 사이트 위변조 방지 설정 (스프링 시큐리티에는 자동으로 설정 되어 있음)
        // csrf기능 켜져있으면 post 요청을 보낼때 csrf 토큰도 보내줘야 로그인 진행됨 !
        // 개발단계에서만 csrf 잠시 꺼두기
        http.csrf((auth) -> auth.disable());
        // http basic 인증 방식 disable 설정
        http.httpBasic((auth -> auth.disable()));
        // 세션 설정
        http.sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        // 새로 만든 로그인 필터를 원래의 (UsernamePasswordAuthenticationFilter)의 자리에 넣음
        http.addFilterAt(new LoginFilter(authenticationManager(configuration), jwtUtil), UsernamePasswordAuthenticationFilter.class);
        // 로그인 필터 이전에 JWTFilter를 넣음
        http.addFilterBefore(new JWTFilter(jwtUtil), LoginFilter.class);
        return http.build();
    }
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder(){ return new BCryptPasswordEncoder(); }
}
