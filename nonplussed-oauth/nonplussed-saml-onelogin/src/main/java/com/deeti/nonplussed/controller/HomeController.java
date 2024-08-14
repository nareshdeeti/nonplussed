package com.deeti.nonplussed.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {

    @GetMapping("/")
    String home(@AuthenticationPrincipal Saml2AuthenticatedPrincipal principle, Model model) {
        model.addAttribute("name", principle.getName());
        model.addAttribute("email", principle.getAttribute("email"));
        return "index";
    }
}
