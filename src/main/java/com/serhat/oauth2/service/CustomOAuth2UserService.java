package com.serhat.oauth2.service;

import com.serhat.oauth2.entity.User;
import com.serhat.oauth2.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oauthUser = super.loadUser(userRequest);
        saveUser(oauthUser);
        return oauthUser;
    }

    private void saveUser(OAuth2User oauthUser) {
        String email = oauthUser.getAttribute("email");
        String name = oauthUser.getAttribute("name");

        Optional<User> existingUser = userRepository.findByEmail(email);

        if (existingUser.isEmpty()) {
            User user = User.builder()
                    .email(email)
                    .name(name)
                    .provider("GOOGLE") // Kullanıcının OAuth sağlayıcısını sakla
                    .password(null) // Şifre Google'dan gelenlerde NULL olabilir
                    .build();
            userRepository.save(user);
        }
    }

}
