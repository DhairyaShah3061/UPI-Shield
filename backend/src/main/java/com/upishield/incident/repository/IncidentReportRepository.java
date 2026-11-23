package com.upishield.incident.repository;

import com.upishield.incident.entity.IncidentReport;
import com.upishield.incident.entity.IncidentStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface IncidentReportRepository extends JpaRepository<IncidentReport, UUID> {

    List<IncidentReport> findByReporterId(UUID reporterId);

    List<IncidentReport> findByStatus(IncidentStatus status);

    List<IncidentReport> findByIndicatorId(UUID indicatorId);
}
