package dev.saha.pgpencryption.controllers;

import dev.saha.pgpencryption.dto.MessageBody;
import dev.saha.pgpencryption.dto.Request;
import dev.saha.pgpencryption.service.KeyGenService;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.sql.Timestamp;
import java.time.LocalDateTime;

@RestController
@RequestMapping("/pgp")
@Slf4j
@RequiredArgsConstructor
@Tag(name = "PGP Encryption", description = "Key Encryption and Decryption")
public class PGPController {

    private final KeyGenService keyGenService;

    @PostMapping(value = "/encrypt",produces = "text/plain")
    public ResponseEntity<MessageBody> encrypt(@RequestBody Request plainText, HttpServletRequest request) {
        log.info("IP => {}",request.getRemoteAddr());
        System.out.println(request.getHeader("X-Forwarded-For"));
        log.info("Encryption Request ==> {}",plainText);
        var output = new MessageBody(keyGenService.encrypt(plainText.getPayload()),
                plainText.getPayload(),
                Timestamp.valueOf(LocalDateTime.now()));
        return new ResponseEntity<>(output,keyGenService.setHeader(), HttpStatus.OK);
    }

    @PostMapping(value = "/decrypt",produces = "text/plain")
    public ResponseEntity<MessageBody> decrypt(@RequestBody Request encryptedText) {
        log.info("Decryption Request ==> {}",encryptedText);
        var output = new MessageBody(encryptedText.getPayload(),
                keyGenService.decrypt(encryptedText.getPayload()),
                Timestamp.valueOf(LocalDateTime.now()));
        return new ResponseEntity<>(output,keyGenService.setHeader(), HttpStatus.OK);
    }
}
