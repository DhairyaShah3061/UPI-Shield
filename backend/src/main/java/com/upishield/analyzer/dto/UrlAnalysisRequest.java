package com.upishield.analyzer.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UrlAnalysisRequest {

    @NotBlank(message = "URL must not be blank")
    @Pattern(
            regexp = "^(https?://)?([a-zA-Z0-9.-]+|\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})(:\\d{1,5})?(/.*)?$",
            message = "Invalid URL format"
    )
    private String url;
}
