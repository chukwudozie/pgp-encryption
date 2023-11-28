package dev.saha.pgpencryption.utils;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.springframework.stereotype.Component;

import java.io.*;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Iterator;
import java.util.Objects;

@Component
public class PGPUtils {

    public static PGPSecretKey createSecretKey(PGPKeyPair keyPair, char[] passPhrase, String keyId, boolean isMasterKey) throws PGPException, NoSuchProviderException {
        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
        PGPSecretKey secretKey = new PGPSecretKey(
                PGPSignature.DEFAULT_CERTIFICATION,
                keyPair,
                keyId,
                sha1Calc,
                null,
                null,
                new JcaPGPContentSignerBuilder(keyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256),
                new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Calc).setProvider("BC").build(passPhrase)
        );
        boolean s = secretKey.isMasterKey();
        if(isMasterKey)s = true;
        return secretKey;
    }


    public static PGPSecretKey createSecretKey2(PGPKeyPair keyPair, char[] passPhrase, String keyID, boolean useSymmetricEncryption) throws PGPException {
        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);


        PBESecretKeyEncryptor encryptor;
        if (useSymmetricEncryption) {
            encryptor = new JcePBESecretKeyEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256).setProvider("BC").build(passPhrase);
        } else {
            PGPPublicKey publicKey = keyPair.getPublicKey();
            encryptor = new JcePBESecretKeyEncryptorBuilder(publicKey.getAlgorithm(), sha1Calc).setProvider("BC").build(passPhrase);
        }

        return new PGPSecretKey(PGPSignature.DEFAULT_CERTIFICATION,
                keyPair, keyID, sha1Calc,
                null,
                null,
                new JcaPGPContentSignerBuilder(keyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256),
                encryptor);
    }

    public static byte[] encrypt(byte[] plaintext, PGPPublicKey publicKey) throws IOException, PGPException {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream out = new ArmoredOutputStream(bOut);

        ByteArrayOutputStream bOut1 = new ByteArrayOutputStream();
        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(PGPCompressedDataGenerator.ZIP);
        OutputStream cos = comData.open(bOut1);

        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();

        OutputStream pOut = lData.open(cos, PGPLiteralData.BINARY, PGPLiteralData.CONSOLE, plaintext.length, new Date());
        pOut.write(plaintext);

        lData.close();
        comData.close();

        PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(
                new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5)
                        .setWithIntegrityPacket(true).setSecureRandom(new SecureRandom())
                        .setProvider("BC"));

        cPk.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(publicKey).setProvider("BC"));

        byte[] bytes = bOut1.toByteArray();

        OutputStream cOut = cPk.open(out, bytes.length);

        cOut.write(bytes);
        cOut.close();

        out.close();

        return bOut.toByteArray();
    }





//    public static byte[] decrypt(byte[] encryptedData, PGPPrivateKey privateKey) throws IOException, PGPException {
//        ByteArrayInputStream bis = new ByteArrayInputStream(encryptedData);
//        InputStream in = PGPUtil.getDecoderStream(bis);
//        JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(in);
//        System.out.println("bis ==> "+bis);
//
//        PGPEncryptedDataList enc;
//        Object o = pgpF.nextObject();
//        System.out.println("Object 0 ==> "+o);
//
//        if (o instanceof PGPEncryptedDataList) {
//            enc = (PGPEncryptedDataList)o;
//        } else {
//            enc = (PGPEncryptedDataList)pgpF.nextObject();
//        }
//
//
//        Iterator<?> it = enc.getEncryptedDataObjects();
//        PGPPrivateKey sKey = null;
//        PGPPublicKeyEncryptedData pbe = null;
//        while (sKey == null && it.hasNext()) {
//            pbe = (PGPPublicKeyEncryptedData)it.next();
//            sKey = privateKey;
//        }
//        System.out.println("I came here oooo");
//
//        if (sKey == null) {
//
//            throw new IllegalArgumentException("Secret key for message not found.");
//        }
//
//        System.out.println("getting data stream  ...");
//        InputStream clear = pbe.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider(new BouncyCastleProvider()).build(sKey));
//
//        System.out.println("clear "+clear);
//
//        JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(clear);
//
//        System.out.println("before");
//        PGPCompressedData cData = (PGPCompressedData) pgpFact.nextObject();
//        System.out.println("c Data => "+cData);
//
//        pgpFact = new JcaPGPObjectFactory(cData.getDataStream());
//
//        PGPLiteralData ld = (PGPLiteralData) pgpFact.nextObject();
//
//        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
//
//        InputStream unc = ld.getInputStream();
//        System.out.println(Objects.isNull(unc));
//        System.out.println(unc);
//        int ch;
//        while ((ch = unc.read()) >= 0) {
//            bOut.write(ch);
//        }
//
//        byte[] uncBytes = bOut.toByteArray();
//        bOut.close();
//        unc.close();
//
//        return uncBytes;
//    }

    public static byte[] decrypt(byte[] encryptedData, PGPPrivateKey privateKey) throws IOException, PGPException {

        if (privateKey == null) {
            throw new IllegalArgumentException("Secret key for message not found.");
        }

        try(ByteArrayInputStream bis = new ByteArrayInputStream(encryptedData); InputStream in = PGPUtil.getDecoderStream(bis)){
            JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(in);
            PGPEncryptedDataList enc = null;
            Object o;

            while ((o = pgpF.nextObject()) != null) {
                if (o instanceof PGPEncryptedDataList) {
                    enc = (PGPEncryptedDataList) o;
                    break;
                }
            }

            if (enc == null) {
                throw new IllegalArgumentException("No PGPEncryptedDataList found in the input data.");
            }

            Iterator<?> it = enc.getEncryptedDataObjects();
            PGPPublicKeyEncryptedData pbe = (PGPPublicKeyEncryptedData) it.next();

            try (InputStream clearStream = pbe.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider(new BouncyCastleProvider()).build(privateKey));
                 ByteArrayOutputStream bOut = new ByteArrayOutputStream()) {
                JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(clearStream);
                PGPCompressedData cData = (PGPCompressedData) pgpFact.nextObject();

                pgpFact = new JcaPGPObjectFactory(cData.getDataStream());
                PGPLiteralData ld = (PGPLiteralData) pgpFact.nextObject();
                try (InputStream unc = ld.getInputStream()) {
                    int ch;
                    while ((ch = unc.read()) >= 0) {
                        bOut.write(ch);
                    }
                }

                return bOut.toByteArray();
            }

        }

    }




    public static PGPPublicKey readPublicKey(InputStream in) throws IOException, PGPException {
        PGPPublicKeyRingCollection keyRingCollection = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(in), new JcaKeyFingerprintCalculator());
        PGPPublicKey key = null;

        Iterator<PGPPublicKeyRing> keyRingIter = keyRingCollection.getKeyRings();
        while (key == null && keyRingIter.hasNext()) {
            PGPPublicKeyRing keyRing = keyRingIter.next();
            Iterator<PGPPublicKey> keyIter = keyRing.getPublicKeys();
            while (key == null && keyIter.hasNext()) {
                PGPPublicKey tmpKey = keyIter.next();
                if (tmpKey.isEncryptionKey()) {
                    key = tmpKey;
                }
            }
        }

        if (key == null) {
            throw new IllegalArgumentException("Can't find encryption key in key ring.");
        }

        return key;
    }

    public static PGPPrivateKey readPrivateKey(InputStream in, char[] passphrase) throws IOException, PGPException {
        PGPSecretKeyRingCollection keyRingCollection = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(in), new JcaKeyFingerprintCalculator());
        PGPSecretKey secretKey = null;

        Iterator<PGPSecretKeyRing> keyRingIter = keyRingCollection.getKeyRings();
        while (secretKey == null && keyRingIter.hasNext()) {
            PGPSecretKeyRing keyRing = keyRingIter.next();
            Iterator<PGPSecretKey> keyIter = keyRing.getSecretKeys();
            while (secretKey == null && keyIter.hasNext()) {
                PGPSecretKey tmpKey = keyIter.next();
                if (tmpKey.isSigningKey()) {
                    secretKey = tmpKey;
                }
            }
        }

        if (secretKey == null) {
            throw new IllegalArgumentException("Can't find signing key in key ring.");
        }

        PBESecretKeyDecryptor decryptor = new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(passphrase);
        return secretKey.extractPrivateKey(decryptor);
    }



}
