package com.upishield.authentication.controller;

import com.upishield.authentication.dto.AuthResponse;
import com.upishield.authentication.dto.LoginRequest;
import com.upishield.authentication.dto.RegisterRequest;
import com.upishield.authentication.dto.UpdatePreferencesRequest;
import com.upishield.authentication.dto.UserProfileResponse;
import com.upishield.authentication.entity.User;
import com.upishield.authentication.repository.UserRepository;
import com.upishield.authentication.service.UserService;
import com.upishield.common.dto.ApiResponse;
import com.upishield.common.exception.BadRequestException;
import com.upishield.common.exception.ResourceNotFoundException;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final UserService userService;
    private final UserRepository userRepository;

    @Autowired
    public AuthController(UserService userService, UserRepository userRepository) {
        this.userService = userService;
        this.userRepository = userRepository;
    }

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<AuthResponse>> register(@Valid @RequestBody RegisterRequest request) {
        AuthResponse response = userService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.success("User registered successfully", response));
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<AuthResponse>> login(@Valid @RequestBody LoginRequest request) {
        AuthResponse response = userService.login(request);
        return ResponseEntity.ok(ApiResponse.success("Login successful", response));
    }

    @GetMapping("/me")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<ApiResponse<UserProfileResponse>> getCurrentUser(Authentication authentication) {
        UUID userId = extractUserId(authentication);
        UserProfileResponse profile = userService.getUserById(userId);
        return ResponseEntity.ok(ApiResponse.success("Profile retrieved successfully", profile));
    }

    @PatchMapping("/me/preferences")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<ApiResponse<UserProfileResponse>> updatePreferences(
            Authentication authentication,
            @RequestBody(required = false) UpdatePreferencesRequest request,
            @RequestParam(name = "lang", required = false) String langParam) {
        UUID userId = extractUserId(authentication);
        String lang = null;
        if (request != null) {
            lang = request.getResolvedLang();
        }
        if (lang == null && langParam != null) {
            lang = langParam;
        }
        if (lang == null || lang.isBlank()) {
            throw new BadRequestException("Language parameter ('preferredLang' or 'lang') is required");
        }

        UserProfileResponse profile = userService.updatePreferences(userId, lang);
        return ResponseEntity.ok(ApiResponse.success("Preferences updated successfully", profile));
    }

    private UUID extractUserId(Authentication authentication) {
        if (authentication == null) {
            authentication = SecurityContextHolder.getContext().getAuthentication();
        }
        if (authentication == null || !authentication.isAuthenticated() || "anonymousUser".equals(authentication.getPrincipal())) {
            throw new BadRequestException("User is not authenticated");
        }

        Object principal = authentication.getPrincipal();
        if (principal instanceof UUID uuid) {
            return uuid;
        }

        String identifier = null;
        if (principal instanceof UserDetails userDetails) {
            identifier = userDetails.getUsername();
        } else if (principal instanceof String str) {
            identifier = str;
        } else {
            identifier = authentication.getName();
        }

        if (identifier != null && !identifier.isBlank()) {
            try {
                return UUID.fromString(identifier);
            } catch (IllegalArgumentException e) {
                // If principal is user's email, look up the UUID
                final String userEmail = identifier;
                return userRepository.findByEmail(userEmail)
                        .map(User::getId)
                        .orElseThrow(() -> new ResourceNotFoundException("User", "email", userEmail));
            }
        }

        throw new BadRequestException("Unable to extract user identity from security context");
    }
}
