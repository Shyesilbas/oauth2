package com.serhat.oauth2.repository;

import com.serhat.oauth2.entity.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<AppUser,Long> {
    Optional<AppUser> findByEmail(String email);
    boolean existsByEmail(String email);

    Optional<AppUser> findByUsername(String username);

    boolean existsByUsername(String username);
}
