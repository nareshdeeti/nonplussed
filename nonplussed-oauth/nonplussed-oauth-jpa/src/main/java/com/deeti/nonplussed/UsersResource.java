package com.deeti.nonplussed;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping("/api/users")
public class UsersResource {

    @GetMapping("/whoami")
    String whoami(Principal principal) {
        return principal.getName();
    }

}
