package com.upishield.authentication.service;

import com.upishield.authentication.dto.AuthResponse;
import com.upishield.authentication.dto.LoginRequest;
import com.upishield.authentication.dto.RegisterRequest;
import com.upishield.authentication.dto.UserProfileResponse;
import com.upishield.authentication.entity.User;
import com.upishield.authentication.entity.UserRole;
import com.upishield.authentication.repository.UserRepository;
import com.upishield.common.exception.BadRequestException;
import com.upishield.common.exception.ResourceNotFoundException;
import com.upishield.common.security.JwtTokenProvider;
import com.upishield.common.util.CredentialSanitizer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;

    @Autowired
    public UserService(UserRepository userRepository,
                       PasswordEncoder passwordEncoder,
                       JwtTokenProvider jwtTokenProvider) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        if (request == null) {
            throw new BadRequestException("Registration request cannot be null");
        }

        String normalizedEmail = request.getEmail().trim().toLowerCase();

        if (userRepository.existsByEmail(normalizedEmail)) {
            throw new BadRequestException("User with email '" + normalizedEmail + "' already exists");
        }

        String emailHash = hashEmail(normalizedEmail);
        String passwordHash = passwordEncoder.encode(request.getPassword());
        String preferredLang = request.getPreferredLang();

        User user = User.builder()
                .email(normalizedEmail)
                .emailHash(emailHash)
                .passwordHash(passwordHash)
                .preferredLang(preferredLang)
                .role(UserRole.STANDARD_USER)
                .build();

        User savedUser = userRepository.save(user);

        String token = jwtTokenProvider.generateToken(
                savedUser.getId(),
                savedUser.getEmail(),
                savedUser.getRole().name()
        );

        return AuthResponse.builder()
                .token(token)
                .tokenType("Bearer")
                .userId(savedUser.getId())
                .role(savedUser.getRole().name())
                .build();
    }

    @Transactional(readOnly = true)
    public AuthResponse login(LoginRequest request) {
        if (request == null) {
            throw new BadRequestException("Login request cannot be null");
        }

        String normalizedEmail = request.getEmail().trim().toLowerCase();

        User user = userRepository.findByEmail(normalizedEmail)
                .orElseThrow(() -> new BadRequestException("Invalid email or password"));

        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            throw new BadRequestException("Invalid email or password");
        }

        String token = jwtTokenProvider.generateToken(
                user.getId(),
                user.getEmail(),
                user.getRole().name()
        );

        return AuthResponse.builder()
                .token(token)
                .tokenType("Bearer")
                .userId(user.getId())
                .role(user.getRole().name())
                .build();
    }

    @Transactional(readOnly = true)
    public UserProfileResponse getUserById(UUID userId) {
        if (userId == null) {
            throw new BadRequestException("User ID must not be null");
        }

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", userId));

        return UserProfileResponse.from(user);
    }

    @Transactional
    public UserProfileResponse updatePreferences(UUID userId, String lang) {
        if (userId == null) {
            throw new BadRequestException("User ID must not be null");
        }
        if (lang == null || lang.isBlank()) {
            throw new BadRequestException("Preferred language must not be blank");
        }

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", userId));

        user.setPreferredLang(lang.trim().toLowerCase());
        User updatedUser = userRepository.save(user);

        return UserProfileResponse.from(updatedUser);
    }

    @Transactional(readOnly = true)
    public User findUserById(UUID userId) {
        if (userId == null) {
            throw new BadRequestException("User ID must not be null");
        }

        return userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", userId));
    }

    public String hashEmail(String email) {
        if (email == null) {
            return null;
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(email.trim().toLowerCase().getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }
}
