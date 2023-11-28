package dev.saha.pgpencryption.dto;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface PubKeyRepository extends JpaRepository<KeyStore, Long> {

    Optional<KeyStore> findByClientId(String clientId);
    boolean existsByClientId(String clientId);

    boolean existsByEncodedValue(String encodedValue);
}
