package com.oauth2_jwt.security.config;

import com.oauth2_jwt.domain.auth.service.CustomOAuth2UserService;
import com.oauth2_jwt.security.handler.CustomSuccessHandler;
import com.oauth2_jwt.security.jwt.JWTFilter;
import com.oauth2_jwt.security.jwt.JWTUtil;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
public class SecurityConfig {

    private final CustomOAuth2UserService customOAuth2UserService;
    private final CustomSuccessHandler customSuccessHandler;
    private final JWTUtil jwtUtil;

//    private final CustomSuccessHandler customSuccessHandler;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http.cors(corsCustomizer -> corsCustomizer.configurationSource(new CorsConfigurationSource() {
            @Override
            public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                CorsConfiguration configuration = new CorsConfiguration();

                configuration.setAllowedOrigins(Collections.singletonList("http://localhost:3000"));
                configuration.setAllowedMethods(Collections.singletonList("*"));
                configuration.setAllowCredentials(true);
                configuration.setAllowedHeaders(Collections.singletonList("*"));
                configuration.setMaxAge(3600L);
                configuration.setExposedHeaders(Collections.singletonList("Authorization"));
                return configuration;
            }
        }));

        // CSRF 보호 비활성화
        http.csrf(AbstractHttpConfigurer::disable);

        // 폼 로그인 비활성화
        http.formLogin(AbstractHttpConfigurer::disable);

        // HTTP Basic 인증 비활성화
        http.httpBasic(AbstractHttpConfigurer::disable);

        // OAuth2 로그인 설정
        http.oauth2Login(oauth2 -> oauth2.userInfoEndpoint(userInfo -> userInfo.userService(customOAuth2UserService))
                        .successHandler(customSuccessHandler)
        );

        // JWT 필터 설정
        http.addFilterBefore(new JWTFilter(jwtUtil), UsernamePasswordAuthenticationFilter.class);

        // 세션 설정: STATELESS
        http.sessionManagement(session -> session.sessionCreationPolicy(STATELESS));

        // 경로별 인가 작업
        http.securityMatcher("/**") // 모든 요청에 대해
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(WHITE_LIST_URL).permitAll()
                        .anyRequest().authenticated()
                );
        return http.build();
    }

    private static final String[] WHITE_LIST_URL = {
            "/",
            "/swagger-ui.html"
    };

}
