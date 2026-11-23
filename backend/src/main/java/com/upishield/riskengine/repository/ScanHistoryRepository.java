package com.upishield.riskengine.repository;

import com.upishield.riskengine.entity.ScanHistory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface ScanHistoryRepository extends JpaRepository<ScanHistory, UUID> {

    Page<ScanHistory> findByUserIdOrderByCreatedAtDesc(UUID userId, Pageable pageable);
}
