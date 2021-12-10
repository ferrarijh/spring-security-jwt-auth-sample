package com.jonathan.jwtauth.api;

import com.jonathan.jwtauth.domain.AppUser;
import com.jonathan.jwtauth.domain.AppUserRole;
import com.jonathan.jwtauth.service.AppUserService;
import lombok.Data;
import lombok.RequiredArgsConstructor;
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

    @PostMapping(path = "/user")
    public ResponseEntity<AppUser> registerUser(@RequestBody AppUser user){
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/user").toUriString());
        return ResponseEntity.created(uri).body(userService.saveUser(user));
    }

    @PostMapping(path = "/role")
    public ResponseEntity<AppUserRole> saveRole(@RequestBody AppUserRole role){
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/role").toUriString());
        return ResponseEntity.created(uri).body(userService.saveRole(role));
    }

    @PostMapping(path = "/user/add-role")
    public ResponseEntity<?> userAddRole(@RequestBody UserAddRoleForm form){
        userService.addRoleToUser(form.getUsername(), form.getRoleName());
        return ResponseEntity.ok().build();
    }
}

@Data
class UserAddRoleForm{
    private String username;
    private String roleName;
}