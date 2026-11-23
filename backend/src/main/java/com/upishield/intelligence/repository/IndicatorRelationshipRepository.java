package com.upishield.intelligence.repository;

import com.upishield.intelligence.entity.IndicatorRelationship;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface IndicatorRelationshipRepository extends JpaRepository<IndicatorRelationship, UUID> {

    List<IndicatorRelationship> findBySourceIndicatorId(UUID sourceId);

    List<IndicatorRelationship> findByTargetIndicatorId(UUID targetId);

    @Query("SELECT r FROM IndicatorRelationship r WHERE r.sourceIndicatorId = :indicatorId OR r.targetIndicatorId = :indicatorId")
    List<IndicatorRelationship> findByIndicatorId(@Param("indicatorId") UUID indicatorId);
}
