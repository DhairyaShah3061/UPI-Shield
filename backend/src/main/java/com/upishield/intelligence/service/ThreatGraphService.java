package com.upishield.intelligence.service;

import com.upishield.intelligence.dto.ThreatIndicatorDto;
import com.upishield.intelligence.entity.IndicatorRelationship;
import com.upishield.intelligence.repository.IndicatorRelationshipRepository;
import com.upishield.intelligence.repository.ThreatIndicatorRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class ThreatGraphService {

    private final IndicatorRelationshipRepository relationshipRepository;
    private final ThreatIndicatorRepository threatIndicatorRepository;

    /**
     * Traverse indicator_relationships up to maxHops (1-2) to find linked threat indicators.
     * For now, implements 1-hop traversal (extensible up to 2 hops).
     *
     * @param indicatorId the starting threat indicator ID
     * @param maxHops the maximum number of traversal hops (1 or 2)
     * @return List of linked ThreatIndicatorDto objects
     */
    @Transactional(readOnly = true)
    public List<ThreatIndicatorDto> getLinkedIndicators(UUID indicatorId, int maxHops) {
        if (indicatorId == null || maxHops < 1) {
            return Collections.emptyList();
        }

        int effectiveHops = Math.min(maxHops, 2);
        Set<UUID> visited = new HashSet<>();
        visited.add(indicatorId);

        Set<UUID> currentFrontier = new HashSet<>();
        currentFrontier.add(indicatorId);

        Set<UUID> allLinkedIds = new HashSet<>();

        for (int hop = 0; hop < effectiveHops; hop++) {
            Set<UUID> nextFrontier = new HashSet<>();
            for (UUID currentId : currentFrontier) {
                List<IndicatorRelationship> rels = relationshipRepository.findByIndicatorId(currentId);
                for (IndicatorRelationship rel : rels) {
                    UUID neighbor = rel.getSourceIndicatorId().equals(currentId)
                            ? rel.getTargetIndicatorId()
                            : rel.getSourceIndicatorId();
                    if (neighbor != null && !visited.contains(neighbor)) {
                        visited.add(neighbor);
                        nextFrontier.add(neighbor);
                        allLinkedIds.add(neighbor);
                    }
                }
            }
            if (nextFrontier.isEmpty()) {
                break;
            }
            currentFrontier = nextFrontier;
        }

        if (allLinkedIds.isEmpty()) {
            return Collections.emptyList();
        }

        return threatIndicatorRepository.findAllById(allLinkedIds)
                .stream()
                .map(ThreatIndicatorDto::fromEntity)
                .toList();
    }
}
