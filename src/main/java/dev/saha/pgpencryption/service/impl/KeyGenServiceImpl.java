package dev.saha.pgpencryption.service.impl;

import com.kelmorgan.encrypterservice.service.Encrypter;
import dev.saha.pgpencryption.service.KeyGenService;
import dev.saha.pgpencryption.utils.PGPUtils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;

import java.io.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;
import java.util.Base64;
import java.util.Date;

import static dev.saha.pgpencryption.utils.PGPUtils.createSecretKey;
import static dev.saha.pgpencryption.utils.PGPUtils.readPublicKey;

@Service
@Slf4j
public class KeyGenServiceImpl implements KeyGenService {

    private static final String PRIVATE_KEY_FILE = "src/main/resources/uba_tokenization_test_1_0xA62DD025_SECRET.asc";
    private static final char[] PASSPHRASE = "1234567890".toCharArray();
    @Value("${secretKey.passphrase}")
    private String passphrase;

    @Value("${secretKey.path}")
    private String privateKey;

    @Value("${publicKey.path}")
    private String pubKey;


    @Override
//    @PostConstruct
    public  void generateKeysAndStore() {
        try {
            Security.addProvider(new BouncyCastleProvider());
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
            keyPairGenerator.initialize(4096);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            PGPKeyPair pgpKeyPair = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, keyPair, new Date());
            PGPSecretKey secretKey = createSecretKey(pgpKeyPair, getPassphrase(), "test-key", true);
            FileOutputStream secret = new FileOutputStream(privateKey);
            secretKey.encode(secret);
            secret.close();

            PGPPublicKey publicKey = pgpKeyPair.getPublicKey();
            FileOutputStream publicOut = new FileOutputStream(pubKey);
            publicKey.encode(publicOut);
            publicOut.close();
            log.info("Keys generated ...");
        }catch (Exception ex){
            log.error("Exception generating keys == > {}",ex.getMessage());
        }
    }

    @Override
    public String encrypt(String plainText) {
        try{
            System.out.println("in ");
            Security.addProvider(new BouncyCastleProvider());
//            PGPPublicKey publicKey = readPublicKey(new FileInputStream(pubKey));
            PGPPublicKey publicKey1 = readPublicKey(new FileInputStream("src/main/resources/UBA_CREATE_PIN_0x1843D890_public.asc"));
            System.out.println("Public key ==> "+publicKey1);
//            byte[] encrypted = PGPUtils.encrypt(plainText.getBytes(), publicKey);
            byte[] encrypted1 = PGPUtils.encrypt(plainText.getBytes(), publicKey1);
            log.info("Byte array generated after encryption");
            return new String(encrypted1);
        }catch (Exception e){
            log.error("Exception in encryption : :{}",e.getMessage());
            return "INVALID ENCRYPTION";
        }
    }

    @Override
    public String decrypt(String encryptedText) {
        try{
            Security.addProvider(new BouncyCastleProvider());
//            PGPPrivateKey privateKey1 = PGPUtils.readPrivateKey(new FileInputStream(privateKey), getPassphrase());
            PGPPrivateKey privateKey1 = PGPUtils.readPrivateKey(new FileInputStream("src/main/resources/UBA_CREATE_PIN_0x1843D890_SECRET.asc"), "123454321".toCharArray());
            System.out.println("Private key ==> "+privateKey1);
            byte[] decrypted1 = PGPUtils.decrypt(encryptedText.getBytes(), privateKey1);
            log.info("Byte array generated after decryption");
            return new String(decrypted1);
        }catch (Exception e){
            log.error("Exception in decryption : {}",e.getMessage());
        }
        return "INVALID DECRYPTION";
    }


    @Override
    public String encryptData(String plainText, PublicKey publicKey) throws PGPException, IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(byteArrayOutputStream);
        PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator
                (new BcPGPDataEncryptorBuilder(PGPEncryptedData.CAST5));
        encryptedDataGenerator.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator((PGPPublicKey) publicKey));
        OutputStream outputStream = encryptedDataGenerator.open(armoredOutputStream, new byte[10]);
        outputStream.write(plainText.getBytes());
        outputStream.close();
        armoredOutputStream.close();
        return byteArrayOutputStream.toString();
    }

    @Override
  public HttpHeaders setHeader(){
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.setContentType(MediaType.APPLICATION_JSON);
        return httpHeaders;
   }

    private char[] getPassphrase(){
        try{
            System.out.println("Passphrase passed :: "+passphrase);
            var decrypted =  Encrypter.decryptSecret(passphrase);
            System.out.println("Passphrase: "+decrypted);
            return decrypted.toCharArray();
        }catch (Exception e){
            log.error("Error in getting passphrase : {}",e.getMessage());
            return new char[0];
        }

    }

    public String encodePublicKeyToBase64(String publicKeyPath) throws IOException, PGPException {
        try(InputStream inputStream = new FileInputStream(publicKeyPath)) {

            PGPPublicKey publicKey = extractPublicKey(inputStream);
            return encodeKey(publicKey);

        }

    }

    private String encodeKey(PGPPublicKey publicKey) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        publicKey.encode(byteArrayOutputStream);
        byte[] publicKeyBytes = byteArrayOutputStream.toByteArray();
        return Base64.getEncoder().encodeToString(publicKeyBytes);
    }

    private PGPPublicKey extractPublicKey(InputStream inputStream) throws IOException, PGPException {
        PGPPublicKeyRingCollection keyRingCollection = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(inputStream), new JcaKeyFingerprintCalculator());
        PGPPublicKeyRing keyRing = keyRingCollection.getKeyRings().next();
        return keyRing.getPublicKey();
    }

    public String encrypt2(String plaintText, String clientId) throws PGPException, IOException {
        Security.addProvider(new BouncyCastleProvider());
        String base64 = encodePublicKeyToBase64("src/main/resources/uba_tokenization_test_1_0xA62DD025_public.asc");
        byte[] publicKeyBytes = Base64.getDecoder().decode(base64);
        var pub = readPublicKey(new ByteArrayInputStream(publicKeyBytes));

        byte[] encryptedData = PGPUtils.encrypt(plaintText.getBytes(), pub);
        return new String(encryptedData);
    }

    public static void main(String[] args) throws PGPException, IOException {
        KeyGenServiceImpl service = new KeyGenServiceImpl();

        System.out.println(service.encrypt2("Emeka", ""));

    }


}
