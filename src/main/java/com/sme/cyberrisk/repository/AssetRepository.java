package com.sme.cyberrisk.repository;

import com.sme.cyberrisk.model.Asset;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface AssetRepository extends JpaRepository<Asset, Long> {
    List<Asset> findByActiveTrue();
    long countByActiveTrue();
}
