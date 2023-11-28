package dev.saha.pgpencryption.dto;

import jakarta.persistence.*;
import lombok.*;



import java.time.LocalDateTime;

@Entity
@Table(name = "keystore")
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@ToString
public class KeyStore {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true)
    private String clientId;
    private String type;
    private LocalDateTime createdAt;
    @Column(length = 17000, unique = true)
    private String encodedValue;
}
