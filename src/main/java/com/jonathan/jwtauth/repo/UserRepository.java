package com.jonathan.jwtauth.repo;

import com.jonathan.jwtauth.domain.entity.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<AppUser, Long> {
    AppUser findByUsername(String username);
}
