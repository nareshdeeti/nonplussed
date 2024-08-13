package com.deeti.nonplussed;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/logged-user")
class LoggedUserController {

    @GetMapping
    Object loggedUser() {
        return SecurityContextHolder.getContext()
                .getAuthentication()
                .getDetails();
    }
}
