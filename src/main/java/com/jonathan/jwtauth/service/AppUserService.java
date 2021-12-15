package com.jonathan.jwtauth.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.common.net.HttpHeaders;
import com.jonathan.jwtauth.domain.dto.RefreshTokenRequestDto;
import com.jonathan.jwtauth.domain.dto.RefreshTokenResponseDto;
import com.jonathan.jwtauth.domain.entity.AppUser;
import com.jonathan.jwtauth.domain.entity.AppUserRole;
import com.jonathan.jwtauth.repo.RoleRepository;
import com.jonathan.jwtauth.repo.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import javax.transaction.Transactional;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class AppUserService implements UserDetailsService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JWTVerifier jwtVerifier;
    private final Algorithm algorithm;

    public AppUser registerUser(AppUser user){
        user.getRoles().add(roleRepository.findByName("ROLE_USER"));
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }

    public AppUserRole addRole(AppUserRole role){
        return roleRepository.save(role);
    }

    public void addRoleToUser(String username, String roleName) {
        AppUser user = userRepository.findByUsername(username);
        AppUserRole role = roleRepository.findByName(roleName);
        user.getRoles().add(role);
    }

    public AppUser getUser(String username){
        return userRepository.findByUsername(username);
    }

    public List<AppUser> getAllUsers(){
        return userRepository.findAll();
    }

    public RefreshTokenResponseDto refreshAccessToken(RefreshTokenRequestDto requestDto) throws JWTVerificationException {
        if(!requestDto.getGrant_type().equals("refresh_token"))
            throw new JWTVerificationException("grant type must be 'refresh_token'");

        DecodedJWT decodedJWT = jwtVerifier.verify(requestDto.getRefresh_token());
        String newAccessToken = JWT.create()
                .withSubject(decodedJWT.getSubject())
                .withExpiresAt(new Date(System.currentTimeMillis() + 20 * 1000))
                .withClaim("roles", decodedJWT.getClaim("roles").asList(String.class))
                .sign(algorithm);
        return new RefreshTokenResponseDto(newAccessToken, "example", 600L);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AppUser user = userRepository.findByUsername(username);
        if(user == null)
            throw new UsernameNotFoundException("user not found in db");

        return User
                .withUsername(username)
                .password(user.getPassword())
                .authorities(
                        user.getRoles().stream()
                                .map(r -> new SimpleGrantedAuthority(r.getName()))
                                .collect(Collectors.toList())
                ).build();
    }
}
