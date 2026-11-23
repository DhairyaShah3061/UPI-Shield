package com.upishield.common.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ErrorResponse {

    @Builder.Default
    private boolean success = false;

    private int status;

    private String error;

    private String message;

    private List<String> details;

    @Builder.Default
    private Instant timestamp = Instant.now();

    public ErrorResponse(int status, String error, String message) {
        this.success = false;
        this.status = status;
        this.error = error;
        this.message = message;
        this.timestamp = Instant.now();
    }

    public ErrorResponse(int status, String error, String message, List<String> details) {
        this.success = false;
        this.status = status;
        this.error = error;
        this.message = message;
        this.details = details;
        this.timestamp = Instant.now();
    }
}
