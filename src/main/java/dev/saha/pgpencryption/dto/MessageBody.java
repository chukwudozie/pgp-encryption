package dev.saha.pgpencryption.dto;

import lombok.*;

import java.sql.Timestamp;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class MessageBody {
    private String encryptedText;
    private String plainText;
    private Timestamp createdTime;
}
