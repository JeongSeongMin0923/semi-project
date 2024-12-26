package com.example.anysale.config;

import com.example.anysale.security.handler.LoginSuccessHandler;
import com.example.anysale.security.service.MemberUserDetailsService;
import lombok.extern.log4j.Log4j2;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@Log4j2
public class SecurityConfig {
  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http, MemberUserDetailsService memberUserDetailsService) throws Exception {
    log.info("---------------filterChain---------------");

        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/","/products","/product/**","/products/**","/member/login", "/member/register", "/css/**", "/js/**","/review/list", "/member/**", "/assets/**", "/likeList/**").permitAll() // 로그인, 회원가입 및 정적 자원은 모두에게 허용
                        .requestMatchers("/member/adminPage").hasRole("ADMIN") // ROLE_ADMIN만 접근 가능
                        .anyRequest().hasRole("USER")// 그 외 모든 요청은 인증 필요
                )
                .formLogin(form -> form
                        .loginPage("/member/login")
                        .defaultSuccessUrl("/products", true) // 로그인 성공 후 항상 products 페이지로 리다이렉트
                        .permitAll()
                        .successHandler(successHandler())
                        .failureUrl("/member/login")
                        .usernameParameter("id")
                        .passwordParameter("password")
                )
                .logout(logout -> logout
                        .logoutUrl("/member/logout")
                        .logoutSuccessUrl("/member/logout")
                        .permitAll()
                )
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/member/login")
                        .defaultSuccessUrl("/products", true)
                        .failureUrl("/member/login")
                        .successHandler(successHandler())
                )
                .rememberMe(rem -> {
                    rem.rememberMeParameter("remember");
                    rem.tokenValiditySeconds(60 * 60 * 24 * 7);
                    rem.userDetailsService(memberUserDetailsService);
                });

    return http.build();
  }

  @Bean
  public LoginSuccessHandler successHandler() {
    return new LoginSuccessHandler();
  }
}