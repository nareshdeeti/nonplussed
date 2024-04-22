package com.deeti.nonplussed;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
class NonplussedController {

    private final NonplussedService nonplussedService;

    NonplussedController(NonplussedService nonplussedService) {
        this.nonplussedService = nonplussedService;
    }

    @GetMapping("/nonplussed")
    String nonplussed() {

        String oauthRest = nonplussedService.oauthRest();
        return "Yo ho ho hoo, you got it " + oauthRest;
    }

    @GetMapping("/oauthRest")
    String oauthRest() {
        return "Amma Baboi";
    }

}
