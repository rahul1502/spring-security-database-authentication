package com.example.security.security;

import com.example.security.auth.ApplicationUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import java.util.concurrent.TimeUnit;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;
    private final ApplicationUserService applicationUserService;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder,
                                     ApplicationUserService applicationUserService) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
                .antMatchers("/api/**").hasRole(ApplicationUserRole.STUDENT.name())
                // .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
                // .antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
                // .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
                // .antMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(ApplicationUserRole.ADMIN.name(), ApplicationUserRole.ADMINTRAINEE.name())
                .anyRequest()
                .authenticated() // this means any request must be authenticated (the client must specify the username and password)
                .and()
                .formLogin()
                    .loginPage("/login")
                    .permitAll()
                    .defaultSuccessUrl("/batcave", true)
                    .usernameParameter("username")
                    .passwordParameter("password")
                .and()
                .rememberMe()
                    .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(30))
                    .key("secret-key")
                .and()
                .logout()
                    .logoutUrl("/logout")
                    .clearAuthentication(true)
                    .invalidateHttpSession(true)
                    .deleteCookies("JSESSIONID", "remember-me")
                    .logoutSuccessUrl("/login");
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {

        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);

        return provider;
    }

//    @Override
//    @Bean // this user will be instantiated when we run the code
//    protected UserDetailsService userDetailsService() {
//
//        // build a user and store it to in-memory database
//        UserDetails rahul = User.builder()
//                .username("rvala")
//                .password(passwordEncoder.encode("password")) // pass the encoded password
//                // .roles(ApplicationUserRole.STUDENT.name()) // ROLE_STUDENT
//                .authorities(ApplicationUserRole.STUDENT.getGrantedAuthorities())
//                .build();
//
//        // build a user with Admin role
//        UserDetails batman = User.builder()
//                .username("batman")
//                .password(passwordEncoder.encode("admin123"))
//                // .roles(ApplicationUserRole.ADMIN.name()) // ROLE_ADMIN
//                .authorities(ApplicationUserRole.ADMIN.getGrantedAuthorities())
//                .build();
//
//        // Build a user with Admin Trainee role
//        UserDetails robin = User.builder()
//                .username("robin")
//                .password(passwordEncoder.encode("admin123"))
//                // .roles(ApplicationUserRole.ADMINTRAINEE.name()) // ROLE_ADMINTRAINEE
//                .authorities(ApplicationUserRole.ADMINTRAINEE.getGrantedAuthorities())
//                .build();
//
//        // fetch the built user from the in-memory database
//        return new InMemoryUserDetailsManager(
//            rahul, batman, robin
//        );
//    }
}
