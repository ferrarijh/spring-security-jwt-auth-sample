package com.jonathan.jwtauth;

import com.jonathan.jwtauth.domain.entity.AppUser;
import com.jonathan.jwtauth.domain.entity.AppUserRole;
import com.jonathan.jwtauth.service.AppUserService;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.util.ArrayList;

@SpringBootApplication
public class JwtAuthApplication {

	public static void main(String[] args) {
		SpringApplication.run(JwtAuthApplication.class, args);
	}

	@Bean
	public ApplicationRunner applicationRunner(AppUserService userService){
		return (args) -> {
			userService.addRole(new AppUserRole(null, "ROLE_USER"));
			userService.addRole(new AppUserRole(null, "ROLE_ADMIN"));
			userService.addRole(new AppUserRole(null, "ROLE_ADMIN_TRAINEE"));

			userService.registerUser(new AppUser(null, "admin", "password", new ArrayList<>()));
			userService.registerUser(new AppUser(null, "elise", "password", new ArrayList<>()));
			userService.registerUser(new AppUser(null, "jiho", "password", new ArrayList<>()));

			userService.addRoleToUser("admin", "ROLE_ADMIN");
			userService.addRoleToUser("elise", "ROLE_ADMIN_TRAINEE");
		};
	}
}
