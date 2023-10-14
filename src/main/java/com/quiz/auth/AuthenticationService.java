package com.quiz.auth;

import com.quiz.exceptions.RegistrationException;
import com.quiz.user.Role;
import com.quiz.user.User;
import com.quiz.user.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Optional;

@Service

public class AuthenticationService {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;

    public User registerUser(User user) throws RegistrationException {
        String email = user.getEmail();
        Optional<User> userWithThatEmail = userRepository.findByEmail(email);

        if (userWithThatEmail.isPresent()) {
            throw new RegistrationException("User with the same email already exists");
        }
        String hashedPwd = passwordEncoder.encode(user.getPassword());
        user.setPassword(hashedPwd);
        user.setCreateDate(String.valueOf(new Date(System.currentTimeMillis())));
        user.setRole(Role.USER);
        return userRepository.save(user);
    }

    public User authenticateUser(String email)  throws UsernameNotFoundException{
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }
}