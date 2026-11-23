package com.upishield.analyzer.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ContentExtractionResult {

    @Builder.Default
    private List<String> urls = new ArrayList<>();

    @Builder.Default
    private List<String> vpas = new ArrayList<>();

    @Builder.Default
    private List<String> phoneNumbers = new ArrayList<>();

    @Builder.Default
    private List<String> amounts = new ArrayList<>();
}
