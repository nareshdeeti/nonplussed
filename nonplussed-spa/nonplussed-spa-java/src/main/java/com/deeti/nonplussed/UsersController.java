package com.deeti.nonplussed;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collection;

@RestController
@RequestMapping("/users")
class UsersController {

    private final AuthenticationManager authenticationManager;

    UsersController(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @GetMapping("/me")
    UserVo me(Authentication authentication, HttpServletResponse response) {
        Collection<String> headerNames = response.getHeaderNames();
        System.out.println(headerNames);
        return new UserVo(authentication.getName(), null);
    }

    /*@PostMapping("/login")
    String login(@RequestBody UserVo user) {

    }*/

    @PostMapping("/login")
    UserVo login(@RequestBody UserVo userCreds) {
        Authentication authenticationRequest = UsernamePasswordAuthenticationToken.unauthenticated(userCreds.username(), userCreds.password());
        Authentication authenticationResponse = this.authenticationManager.authenticate(authenticationRequest);

        if (authenticationResponse.isAuthenticated()) {
            return new UserVo(authenticationResponse.getName(), null);
        }

        return new UserVo(null, null);
    }

}
