package com.jonathan.jwtauth.api;

import com.jonathan.jwtauth.domain.dto.RefreshTokenRequestDto;
import com.jonathan.jwtauth.domain.dto.RefreshTokenResponseDto;
import com.jonathan.jwtauth.domain.dto.UserAddRoleRequestDto;
import com.jonathan.jwtauth.domain.entity.AppUser;
import com.jonathan.jwtauth.domain.entity.AppUserRole;
import com.jonathan.jwtauth.service.AppUserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.util.List;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class UserResource {

    private final AppUserService userService;

    @GetMapping(path = "/user/all")
    public ResponseEntity<List<AppUser>> getUsers(){
        return ResponseEntity.ok().body(userService.getAllUsers());
    }

    @PostMapping(path = "/user/register")
    public ResponseEntity<AppUser> registerUser(@RequestBody AppUser user){
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/user/register").toUriString());
        return ResponseEntity.created(uri).body(userService.registerUser(user));
    }

    @PostMapping(path = "/user/add-role")
    public ResponseEntity<?> addRoleToUser(@RequestBody UserAddRoleRequestDto form){
        userService.addRoleToUser(form.getUsername(), form.getRoleName());
        return ResponseEntity.ok().build();
    }

    @PostMapping(path = "/role")
    public ResponseEntity<AppUserRole> addRole(@RequestBody AppUserRole role){
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/role").toUriString());
        return ResponseEntity.created(uri).body(userService.addRole(role));
    }

    @PostMapping(
            path = "/token/refresh",
            consumes = {MediaType.APPLICATION_FORM_URLENCODED_VALUE},
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<RefreshTokenResponseDto> refreshAccessToken(RefreshTokenRequestDto requestDto){
        return ResponseEntity.ok().body(userService.refreshAccessToken(requestDto));
    }
}