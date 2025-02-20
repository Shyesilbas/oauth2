package com.serhat.oauth2.service;

import com.serhat.oauth2.entity.AppUser;
import com.serhat.oauth2.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.Random;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
    private final UserRepository userRepository;
    private final Random random = new Random();


    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oauthUser = super.loadUser(userRequest);
        saveUser(oauthUser);
        return oauthUser;
    }
    public String generateUniqueUsername() {
        String username;
        do {
            username = "user" + (100 + random.nextInt(900));
        } while (userRepository.existsByUsername(username));
        return username;
    }

    private void saveUser(OAuth2User oauthUser) {
        String email = oauthUser.getAttribute("email");
        String name = oauthUser.getAttribute("name");

        Optional<AppUser> existingUser = userRepository.findByEmail(email);

        if (existingUser.isEmpty()) {
            AppUser user = AppUser.builder()
                    .email(email)
                    .username(generateUniqueUsername())
                    .name(name)
                    .provider("GOOGLE")
                    .password(null)
                    .build();
            userRepository.save(user);
        }
    }

}
