package com.sme.cyberrisk.repository;

import com.sme.cyberrisk.model.Finding;
import com.sme.cyberrisk.model.FindingCategory;
import com.sme.cyberrisk.model.Severity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface FindingRepository extends JpaRepository<Finding, Long> {
    List<Finding> findBySeverity(Severity severity);
    List<Finding> findByCategory(FindingCategory category);
    long countBySeverity(Severity severity);
}
