package com.deeti.nonplussed;

import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.config.annotation.web.configurers.HttpBasicConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@EnableWebSecurity(debug = true)
@Configuration
public class SecurityConfiguration {

    @Bean
    SecurityFilterChain defaultSecurity(HttpSecurity httpSecurity) throws Exception {
        CookieCsrfTokenRepository cookieCsrfTokenRepository = CookieCsrfTokenRepository.withHttpOnlyFalse();
//        cookieCsrfTokenRepository.setCookiePath("/");
        return httpSecurity
                .csrf(csrf -> csrf.csrfTokenRepository(cookieCsrfTokenRepository).csrfTokenRequestHandler(new SpaCsrfTokenRequestHandler()))
//                .csrf(csrf -> csrf.csrfTokenRepository(cookieCsrfTokenRepository))
//                .csrf(Customizer.withDefaults())
//                .csrf(csrf -> csrf.disable())
                .cors(cors -> cors.configurationSource(corsConfiguration()))
//                .formLogin(form -> form.defaultSuccessUrl("/users/me", true))
//                .formLogin(Customizer.withDefaults())
//                .formLogin(form -> form.loginProcessingUrl("/users/login").permitAll())
                .formLogin(FormLoginConfigurer::disable)
                .httpBasic(Customizer.withDefaults())
//                .httpBasic(HttpBasicConfigurer::disable)
//                .httpBasic(http -> http.)
                .authorizeHttpRequests((requests) -> requests.requestMatchers("/index.html", "/", "/home", "/login", "/users/login", "/csrf")
                        .permitAll()
                        .anyRequest()
                        .authenticated())
                .addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class)
//                .securityContext((securityCtx) -> securityCtx.securityContextRepository(new HttpSessionSecurityContextRepository()))
                .build();
//                .build();
//                .oauth2ResourceServer((resource) -> resource.jwt((Customizer.withDefaults()))).build();
    }


    CorsConfigurationSource corsConfiguration() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOriginPatterns(List.of("*"));
        configuration.setAllowedOrigins(List.of("*"));
        configuration.setAllowedMethods(List.of("*"));
        configuration.setAllowedHeaders(List.of("*"));
//        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Bean
    UserDetailsService userDetailsService() {
        UserDetails user =  User.builder()
                .username("user")
                .password("password")
                .build();
        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    public AuthenticationManager authenticationManager(UserDetailsService userDetailsService,
                                                       PasswordEncoder passwordEncoder) throws Exception {

        DaoAuthenticationProvider daoAuthProvider = new DaoAuthenticationProvider();
        daoAuthProvider.setUserDetailsService(userDetailsService);
        daoAuthProvider.setPasswordEncoder(passwordEncoder);
        return new ProviderManager(daoAuthProvider);
    }




}

