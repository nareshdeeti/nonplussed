package com.deeti.nonplussed;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
class NonplussedController {

    @GetMapping("/wish")
    String wish(Principal principal) {
        return String.format("Yo, %s", principal.getName());
    }

}
