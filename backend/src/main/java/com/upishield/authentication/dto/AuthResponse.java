package com.upishield.authentication.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponse {

    private String token;

    @Builder.Default
    private String tokenType = "Bearer";

    private UUID userId;

    private String role;

    public AuthResponse(String token, UUID userId, String role) {
        this.token = token;
        this.tokenType = "Bearer";
        this.userId = userId;
        this.role = role;
    }
}
