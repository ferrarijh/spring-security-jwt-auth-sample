package com.jonathan.jwtauth.config;

import com.jonathan.jwtauth.filter.AppAuthenticationFilter;
import com.jonathan.jwtauth.filter.AppAuthorizationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
@RequiredArgsConstructor
public class AppSecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .userDetailsService(userDetailsService)
                .passwordEncoder(passwordEncoder);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        AppAuthenticationFilter appAuthFilter = new AppAuthenticationFilter(authenticationManager());
        appAuthFilter.setFilterProcessesUrl("/api/login");

        http
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                .authorizeRequests()
                        .antMatchers("/api/login").permitAll()
                        .antMatchers(HttpMethod.GET, "/api/user/**").hasAuthority("ROLE_ADMIN")
                        .antMatchers(HttpMethod.POST, "/api/user/**").hasAuthority("ROLE_ADMIN")
                        .anyRequest().authenticated()
                        .and()
                .addFilter(appAuthFilter)
                .addFilterBefore(new AppAuthorizationFilter(), AppAuthenticationFilter.class);
    }

    @Bean
    public AuthenticationManager authenticationManager() throws Exception{
        return super.authenticationManager();
    }
}
