package com.serhat.oauth2.service;

import com.serhat.oauth2.entity.AppUser;
import com.serhat.oauth2.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Random;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oauthUser = super.loadUser(userRequest);
        saveUser(oauthUser);

        return new OAuth2UserDetails(oauthUser);
    }


    public void saveUser(OAuth2User oauthUser) {
        String email = oauthUser.getAttribute("email");
        String name = oauthUser.getAttribute("name");
        String username = oauthUser.getAttribute("sub");
        Optional<AppUser> existingUser = userRepository.findByEmail(email);

        if (existingUser.isEmpty()) {
            AppUser user = AppUser.builder()
                    .email(email)
                    .name(name)
                    .username(username)
                    .provider("GOOGLE")
                    .password(null)
                    .build();
            userRepository.save(user);
        }
    }

}
