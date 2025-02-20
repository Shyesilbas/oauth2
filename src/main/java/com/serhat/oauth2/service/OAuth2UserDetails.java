package com.serhat.oauth2.service;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Map;

public class OAuth2UserDetails extends User implements OAuth2User {
    private final OAuth2User oAuth2User;

    public OAuth2UserDetails(OAuth2User oAuth2User) {
        super(oAuth2User.getName(), "", oAuth2User.getAuthorities());
        this.oAuth2User = oAuth2User;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return oAuth2User.getAttributes();
    }

    @Override
    public String getName() {
        return oAuth2User.getName();
    }
}
