package com.serhat.oauth2.controller;

import com.serhat.oauth2.entity.AppUser;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RequiredArgsConstructor
@RequestMapping("/test")
@RestController
public class UserController {

    @GetMapping("/oauth2Test")
    public String oauth2() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication.getPrincipal() instanceof UserDetails userDetails){
            String username = userDetails.getUsername();
            return  username+" You see this message if you have logged in with Google";

        }
        return "User  not authenticated";
    }


    @GetMapping("/form")
    public String form(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication.getPrincipal() instanceof UserDetails userDetails){
            String username = userDetails.getUsername();
            return  username+" You see this message if you logged in with credentials";

        }
        return "Username not found";
    }
}
