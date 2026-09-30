package com.example.authserver.security;

import com.example.authserver.entity.User;
import com.example.authserver.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

// Runs after Google confirms who the user is.
// Finds or creates the local user, and makes the EMAIL the principal name,
// so the JWT "sub" stays the email, exactly like form login.
@Service
@RequiredArgsConstructor
public class GoogleOidcUserService extends OidcUserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        OidcUser googleUser = super.loadUser(userRequest);

        String email = googleUser.getEmail();
        if (email == null || !Boolean.TRUE.equals(googleUser.getEmailVerified())) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("email_not_verified"),
                    "Google account email is missing or not verified");
        }

        User user = userRepository.findByEmail(email).orElseGet(() -> {
            User newUser = new User();
            newUser.setEmail(email);
            newUser.setName(googleUser.getFullName());
            // Random password: this account can only sign in through Google
            newUser.setPassword(passwordEncoder.encode(UUID.randomUUID().toString()));
            return userRepository.save(newUser);
        });

        List<GrantedAuthority> authorities =
                List.of(new SimpleGrantedAuthority("ROLE_" + user.getRole()));

        // Last argument "email" = use the email claim as the principal name
        return new DefaultOidcUser(authorities, googleUser.getIdToken(), googleUser.getUserInfo(), "email");
    }
}