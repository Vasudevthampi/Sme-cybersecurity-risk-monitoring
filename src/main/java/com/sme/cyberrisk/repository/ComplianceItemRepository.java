package com.sme.cyberrisk.repository;

import com.sme.cyberrisk.model.ComplianceItem;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface ComplianceItemRepository extends JpaRepository<ComplianceItem, Long> {
    List<ComplianceItem> findByNistCategory(String nistCategory);
    long countByStatus(String status);
}
