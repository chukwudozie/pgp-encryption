package dev.saha.pgpencryption.service;

import org.bouncycastle.openpgp.PGPException;
import org.springframework.http.HttpHeaders;

import java.io.IOException;
import java.security.PublicKey;

public interface KeyGenService {

     void generateKeysAndStore();

     String encrypt(String plainText);

     String decrypt(String encryptedText);

     String encryptData(String plainText, PublicKey publicKey) throws PGPException, IOException;

     HttpHeaders setHeader();
}
