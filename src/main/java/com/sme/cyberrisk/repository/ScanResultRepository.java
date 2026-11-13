package com.sme.cyberrisk.repository;

import com.sme.cyberrisk.model.ScanResult;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface ScanResultRepository extends JpaRepository<ScanResult, Long> {
    List<ScanResult> findByAssetIdOrderByScanDateDesc(Long assetId);
    List<ScanResult> findTop10ByOrderByScanDateDesc();
}
