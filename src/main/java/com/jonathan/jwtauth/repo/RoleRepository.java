package com.jonathan.jwtauth.repo;

import com.jonathan.jwtauth.domain.entity.AppUserRole;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<AppUserRole, Long> {
    AppUserRole findByName(String name);
}
