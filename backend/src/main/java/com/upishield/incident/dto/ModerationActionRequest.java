package com.upishield.incident.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ModerationActionRequest {

    @NotBlank(message = "Moderation action is required (VERIFY, DISMISS, REVIEW)")
    private String action;

    private String notes;
}
