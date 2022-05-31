package com.example.security.auth;

import com.example.security.security.ApplicationUserRole;
import com.google.common.collect.Lists;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository("fake")
public class FakeApplicationUserDaoService implements ApplicationUserDao {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public FakeApplicationUserDaoService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    // This method should have the code to fetch the user details from the DB
    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
        return getApplicationUsers()
                .stream()
                .filter(applicationUser -> applicationUser.getUsername().equals(username))
                .findFirst();
    }

    // This is a dummy method to avoid the setup of a real DB
    private List<ApplicationUser> getApplicationUsers() {

        List<ApplicationUser> applicationUsers = Lists.newArrayList(
            new ApplicationUser(
                        "rvala",
                        passwordEncoder.encode("password"),
                        ApplicationUserRole.STUDENT.getGrantedAuthorities(),
                    true,
                    true,
                    true,
                    true
                    ),
            new ApplicationUser(
                    "batman",
                    passwordEncoder.encode("admin123"),
                    ApplicationUserRole.ADMIN.getGrantedAuthorities(),
                    true,
                    true,
                    true,
                    true
            ),
            new ApplicationUser(
                    "robin",
                    passwordEncoder.encode("admin123"),
                    ApplicationUserRole.ADMINTRAINEE.getGrantedAuthorities(),
                    true,
                    true,
                    true,
                    true
            )
        );

        return applicationUsers;
    }
}
