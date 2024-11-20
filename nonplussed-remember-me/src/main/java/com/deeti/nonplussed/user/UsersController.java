package com.deeti.nonplussed.user;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping("/users/")
class UsersController {

    @GetMapping("/current-user")
    String currentUser(Principal authenticatedPrincipal) {
        return authenticatedPrincipal.getName();
    }

}
