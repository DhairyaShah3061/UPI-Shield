package com.upishield.intelligence.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.upishield.intelligence.dto.ThreatIndicatorDto;
import com.upishield.intelligence.entity.ThreatIndicator;
import com.upishield.intelligence.repository.ThreatIndicatorRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Optional;

@Service
@Slf4j
public class ReputationService {

    private static final String CACHE_PREFIX = "threat:indicator:";

    private final ThreatIndicatorRepository threatIndicatorRepository;
    private final HashingService hashingService;
    private final ObjectMapper objectMapper;
    private final StringRedisTemplate redisTemplate;
    private final Duration cacheTtl;

    public ReputationService(
            ThreatIndicatorRepository threatIndicatorRepository,
            HashingService hashingService,
            ObjectMapper objectMapper,
            @Autowired(required = false) StringRedisTemplate redisTemplate,
            @Value("${app.reputation.cache-ttl-minutes:30}") long cacheTtlMinutes) {
        this.threatIndicatorRepository = threatIndicatorRepository;
        this.hashingService = hashingService;
        this.objectMapper = objectMapper;
        this.redisTemplate = redisTemplate;
        this.cacheTtl = Duration.ofMinutes(cacheTtlMinutes);
    }

    /**
     * Lookup reputation for a UPI Virtual Payment Address (VPA).
     * Normalizes, hashes, checks Redis cache first, then DB.
     *
     * @param vpa raw UPI ID (e.g. "fraudster@upi")
     * @return ThreatIndicatorDto if found in cache or DB
     */
    public Optional<ThreatIndicatorDto> lookupVpa(String vpa) {
        return lookup("VPA", vpa);
    }

    /**
     * Lookup reputation for a domain or URL host.
     * Normalizes, hashes, checks Redis cache first, then DB.
     *
     * @param domain domain name (e.g. "scam-verify-upi.com")
     * @return ThreatIndicatorDto if found in cache or DB
     */
    public Optional<ThreatIndicatorDto> lookupDomain(String domain) {
        return lookup("DOMAIN", domain);
    }

    /**
     * Lookup reputation for a phone number.
     * Normalizes, hashes, checks Redis cache first, then DB.
     *
     * @param phone phone number (e.g. "+919876543210")
     * @return ThreatIndicatorDto if found in cache or DB
     */
    public Optional<ThreatIndicatorDto> lookupPhone(String phone) {
        return lookup("PHONE", phone);
    }

    /**
     * Lookup reputation for an indicator by type and raw value.
     * Normalizes, hashes, checks Redis cache first, then PostgreSQL DB.
     * Caches DB hits in Redis with TTL.
     *
     * @param type indicator type (VPA, DOMAIN, PHONE, QR_HASH)
     * @param value raw indicator value
     * @return Optional containing ThreatIndicatorDto if indicator exists
     */
    public Optional<ThreatIndicatorDto> lookup(String type, String value) {
        if (value == null || value.isBlank() || type == null || type.isBlank()) {
            return Optional.empty();
        }

        String normalizedType = type.trim().toUpperCase();
        String hash = hashingService.normalizeAndHash(value);
        String cacheKey = CACHE_PREFIX + normalizedType + ":" + hash;

        // 1. Check Redis Cache
        Optional<ThreatIndicatorDto> cachedDto = getFromCache(cacheKey);
        if (cachedDto.isPresent()) {
            log.debug("Reputation cache HIT for {} key={}", normalizedType, cacheKey);
            return cachedDto;
        }

        // 2. Query Database
        log.debug("Reputation cache MISS for {} key={}, checking database", normalizedType, cacheKey);
        Optional<ThreatIndicator> indicatorOpt = threatIndicatorRepository
                .findByIndicatorTypeAndIndicatorHash(normalizedType, hash);

        if (indicatorOpt.isEmpty()) {
            indicatorOpt = threatIndicatorRepository.findByIndicatorHash(hash);
        }

        if (indicatorOpt.isPresent()) {
            ThreatIndicatorDto dto = ThreatIndicatorDto.fromEntity(indicatorOpt.get());
            saveToCache(cacheKey, dto);
            return Optional.of(dto);
        }

        return Optional.empty();
    }

    private Optional<ThreatIndicatorDto> getFromCache(String cacheKey) {
        if (redisTemplate == null) {
            return Optional.empty();
        }
        try {
            String json = redisTemplate.opsForValue().get(cacheKey);
            if (json != null && !json.isBlank()) {
                ThreatIndicatorDto dto = objectMapper.readValue(json, ThreatIndicatorDto.class);
                return Optional.ofNullable(dto);
            }
        } catch (Exception e) {
            log.warn("Redis read failed for cacheKey {}: {}", cacheKey, e.getMessage());
        }
        return Optional.empty();
    }

    private void saveToCache(String cacheKey, ThreatIndicatorDto dto) {
        if (redisTemplate == null || dto == null) {
            return;
        }
        try {
            String json = objectMapper.writeValueAsString(dto);
            redisTemplate.opsForValue().set(cacheKey, json, cacheTtl);
            log.debug("Stored indicator in Redis cache with TTL {}: key={}", cacheTtl, cacheKey);
        } catch (JsonProcessingException e) {
            log.error("Failed to serialize ThreatIndicatorDto for cacheKey {}", cacheKey, e);
        } catch (Exception e) {
            log.warn("Redis write failed for cacheKey {}: {}", cacheKey, e.getMessage());
        }
    }
}
