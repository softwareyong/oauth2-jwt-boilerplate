package com.oauth2_jwt.domain.auth.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class AuthController {

    @GetMapping("/my")
    public String my() {
        return "my";
    }

}
