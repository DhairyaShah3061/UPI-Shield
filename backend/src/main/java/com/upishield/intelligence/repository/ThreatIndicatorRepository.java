package com.upishield.intelligence.repository;

import com.upishield.intelligence.entity.IndicatorStatus;
import com.upishield.intelligence.entity.ThreatIndicator;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface ThreatIndicatorRepository extends JpaRepository<ThreatIndicator, UUID> {

    Optional<ThreatIndicator> findByIndicatorHash(String hash);

    Optional<ThreatIndicator> findByIndicatorTypeAndIndicatorHash(String type, String hash);

    List<ThreatIndicator> findByStatus(IndicatorStatus status);

    long countByIndicatorHash(String hash);
}
