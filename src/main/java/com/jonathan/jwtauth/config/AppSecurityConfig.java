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
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;

@EnableWebSecurity
@RequiredArgsConstructor
public class AppSecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final AppAuthorizationFilter appAuthorizationFilter;
    private final AccessDeniedHandler accessDeniedHandler;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .userDetailsService(userDetailsService)
                .passwordEncoder(passwordEncoder);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        AppAuthenticationFilter appAuthenticationFilter = new AppAuthenticationFilter(authenticationManager());
        appAuthenticationFilter.setFilterProcessesUrl("/api/login");

        http
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                .exceptionHandling()
                        .accessDeniedHandler(accessDeniedHandler)
                        .and()
                .authorizeRequests()
                        .antMatchers("/api/login").permitAll()
                        .antMatchers("/api/user/register").permitAll()
                        .antMatchers(HttpMethod.GET, "/api/user/**").hasAnyAuthority("ROLE_ADMIN", "ROLE_ADMIN_TRAINEE")
                        .antMatchers(HttpMethod.POST, "/api/user/**").hasAuthority("ROLE_ADMIN")
                        .anyRequest().authenticated()
                        .and()
                .addFilter(appAuthenticationFilter)
                .addFilterBefore(appAuthorizationFilter, AppAuthenticationFilter.class);
    }

    @Bean
    public AuthenticationManager authenticationManager() throws Exception{
        return super.authenticationManager();
    }
}
