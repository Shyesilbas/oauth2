package com.serhat.oauth2.component;

import com.serhat.oauth2.entity.AppUser;
import com.serhat.oauth2.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class Initializer {

    @Bean
    public CommandLineRunner userInitializer(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        return args -> {
            String email = "test2@example.com";

            if (userRepository.findByEmail(email).isEmpty()) {
                AppUser user = AppUser.builder()
                        .username("test2")
                        .email(email)
                        .name("John Test2")
                        .password(passwordEncoder.encode("password123"))
                        .provider("REGISTER")
                        .build();

                userRepository.save(user);

                System.out.println("User created with email: " + user.getEmail());
            } else {
                System.out.println("User with email " + email + " already exists.");
            }
        };
    }
}
