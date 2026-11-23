package com.upishield.authentication.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UpdatePreferencesRequest {

    private String preferredLang;
    private String lang;

    public String getResolvedLang() {
        if (preferredLang != null && !preferredLang.isBlank()) {
            return preferredLang;
        }
        return lang;
    }
}
