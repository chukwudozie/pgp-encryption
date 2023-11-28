package dev.saha.pgpencryption.controllers;

import dev.saha.pgpencryption.dto.MessageBody;
import dev.saha.pgpencryption.dto.KeyStore;
import dev.saha.pgpencryption.dto.PubKeyRepository;
import dev.saha.pgpencryption.dto.Request;
import dev.saha.pgpencryption.service.KeyGenService;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.openpgp.PGPException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@RestController
@RequestMapping("/pgp")
@Slf4j
@RequiredArgsConstructor
@Tag(name = "PGP Encryption", description = "Key Encryption and Decryption")
public class PGPController {

    private final KeyGenService keyGenService;
    private final PubKeyRepository pubKeyRepository;

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


    @PostMapping("register-key")
    public ResponseEntity<?> registerKey(@RequestParam String clientId, @RequestParam MultipartFile key){
        Map<String,String> output = new HashMap<>();
        System.out.println("size => "+key.getSize());
        try {
            String publicKeyBase64 = convertPublicKeyFileToBase64(key);
            savePublicKey(clientId, publicKeyBase64);
            output.put("message","Public key submitted and saved successfully");
            return ResponseEntity.ok(output);
        } catch (Exception e) {
            output.put("message","Error processing and saving public key: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(output);
        }

    }

    private void savePublicKey(String clientId, String publicKeyBase64) throws PGPException {
        if (pubKeyRepository.existsByClientId(clientId)){
            throw new PGPException("Client Id already exists");
        }
        if(pubKeyRepository.existsByEncodedValue(publicKeyBase64)){
            throw new PGPException("This key is already in use");
        }
        KeyStore key = new KeyStore();
        key.setClientId(clientId);
        key.setEncodedValue(publicKeyBase64);
        key.setCreatedAt(LocalDateTime.now());
        pubKeyRepository.save(key);


    }

    private String convertPublicKeyFileToBase64(MultipartFile file) throws IOException, PGPException {
        System.out.println("Original file name "+file.getOriginalFilename());
        if (Objects.nonNull(file.getOriginalFilename()) && !file.getOriginalFilename().contains(".asc")){
            throw new PGPException("Only keys in .asc format can be saved");
        }
        byte[] publicKeyBytes = file.getBytes();
        var base64 =  Base64.getEncoder().encodeToString(publicKeyBytes);
        System.out.println("Base 64 size => "+base64.length());
        if (base64.length() > 18000)
            throw new PGPException("Encoded String should be  less than 18000");
        return base64;
    }
}
