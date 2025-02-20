package com.serhat.oauth2.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RequestMapping("/test")
@RestController
public class UserController {

    @GetMapping("/oauth2Test")
    public String test(){
        return "If you can see this, you have logged in by Google successfully";
    }

}
