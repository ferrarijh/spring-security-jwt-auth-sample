package com.jonathan.jwtauth.domain.dto;

import lombok.Data;

@Data
public class UserAddRoleRequestDto {
    private String username;
    private String roleName;
}