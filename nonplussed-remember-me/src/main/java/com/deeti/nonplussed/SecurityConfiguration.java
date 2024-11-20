package com.deeti.nonplussed;

import com.deeti.nonplussed.user.SimpleUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.RememberMeAuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CorsConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenBasedRememberMeServices;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices;
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices.RememberMeTokenAlgorithm;

import javax.sql.DataSource;

@EnableWebSecurity(debug = true)
@Configuration
public class SecurityConfiguration {

    private final SimpleUserDetailsService userDetailsService;
    private final DataSource dataSource;

    public SecurityConfiguration(SimpleUserDetailsService userDetailsService,
                                 DataSource dataSource) {
        this.userDetailsService = userDetailsService;
        this.dataSource = dataSource;
    }

    @Bean
    SecurityFilterChain defaultSecurity(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .csrf(CsrfConfigurer::disable)
                .cors(CorsConfigurer::disable)
                .formLogin(FormLoginConfigurer::disable)
                .httpBasic(Customizer.withDefaults())
                .authorizeHttpRequests((requests) -> requests.anyRequest().authenticated())
                .userDetailsService(userDetailsService)
                .rememberMe(rememberMe -> rememberMe.rememberMeServices(jdbcTokenBasedRememberMeServices()))
                .build();
    }


    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(14);
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        DaoAuthenticationProvider daoAuthProvider = new DaoAuthenticationProvider();
        daoAuthProvider.setUserDetailsService(userDetailsService);
        daoAuthProvider.setPasswordEncoder(passwordEncoder());
        return new ProviderManager(daoAuthProvider);
    }

    @Bean
    RememberMeServices rememberMeServices(UserDetailsService userDetailsService) {
        RememberMeTokenAlgorithm rememberMeTokenAlgorithm = RememberMeTokenAlgorithm.SHA256;
        TokenBasedRememberMeServices tokenBasedRememberMeServices = new TokenBasedRememberMeServices("nonplussed",
                userDetailsService,
                rememberMeTokenAlgorithm);
        tokenBasedRememberMeServices.setMatchingAlgorithm(RememberMeTokenAlgorithm.MD5);
        return tokenBasedRememberMeServices;
    }

    @Bean
    RememberMeAuthenticationFilter rememberMeAuthenticationFilter() {
        return new RememberMeAuthenticationFilter(authenticationManager(),
                rememberMeServices(userDetailsService));
    }

    @Bean
    PersistentTokenRepository persistentTokenRepository() {
        JdbcTokenRepositoryImpl jdbcTokenRepository = new JdbcTokenRepositoryImpl();
        jdbcTokenRepository.setDataSource(dataSource);
        return jdbcTokenRepository;
    }

    @Bean
    TokenBasedRememberMeServices tokenBasedRememberMeServices() {
        return new TokenBasedRememberMeServices("nonplussed", userDetailsService);
    }

    @Bean
    PersistentTokenBasedRememberMeServices jdbcTokenBasedRememberMeServices() {
        return new PersistentTokenBasedRememberMeServices("nonplussed", userDetailsService, persistentTokenRepository());
    }

    @Bean
    RememberMeAuthenticationProvider rememberMeAuthenticationProvider() {
        return new RememberMeAuthenticationProvider("nonplussed");
    }

}

