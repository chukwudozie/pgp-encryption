package dev.saha.pgpencryption.dto;

import lombok.*;

@Builder
@Getter
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class Request {
    private String payload;
}
