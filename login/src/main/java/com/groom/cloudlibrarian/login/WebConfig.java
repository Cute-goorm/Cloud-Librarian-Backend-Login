package com.groom.cloudlibrarian.login;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {
    public static String domain = "http://localhost:3000"; // 로컬용
//    public static String domain = "[도메인]"; // 배포용 (https:// 제외)
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedOrigins("http://localhost:8080", domain) // 허용할 출처
                .allowedMethods("GET", "POST", "FATCH", "PUT", "DELETE") // 허용할 HTTP method
                .allowedHeaders("Authorization", "Content-Type")
                .allowCredentials(true) // 쿠키 인증 요청 허용
                .maxAge(3000); // 원하는 시간만큼 pre-flight 리퀘스트를 캐싱
    }
}
