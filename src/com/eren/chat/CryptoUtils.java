package com.eren.chat;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


public class CryptoUtils {


    public static void generateRsaKeyPair(String publicKeyPath, String privateKeyPath) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
        PublicKey publicKey = pair.getPublic();
        PrivateKey privateKey = pair.getPrivate();

        writePublicKeyAsPem(publicKey, publicKeyPath);
        writePrivateKeyAsPem(privateKey, privateKeyPath);
    }


    private static void writePublicKeyAsPem(PublicKey publicKey, String filePath) throws IOException {
        byte[] derBytes = publicKey.getEncoded();                           
        String base64 = Base64.getEncoder().encodeToString(derBytes);        
        String pemContent = "-----BEGIN PUBLIC KEY-----\n"
                + wrapBase64(base64)
                + "-----END PUBLIC KEY-----\n";
        Files.write(Paths.get(filePath), pemContent.getBytes());
    }


    private static void writePrivateKeyAsPem(PrivateKey privateKey, String filePath) throws IOException {
        byte[] derBytes = privateKey.getEncoded();                           
        String base64 = Base64.getEncoder().encodeToString(derBytes);
        String pemContent = "-----BEGIN PRIVATE KEY-----\n"
                + wrapBase64(base64)
                + "-----END PRIVATE KEY-----\n";
        Files.write(Paths.get(filePath), pemContent.getBytes());
    }

    private static String wrapBase64(String base64) {
        StringBuilder sb = new StringBuilder();
        int index = 0, lineLength = 64;
        while (index < base64.length()) {
            int endIndex = Math.min(index + lineLength, base64.length());
            sb.append(base64, index, endIndex).append("\n");
            index = endIndex;
        }
        return sb.toString();
    }

    public static PublicKey loadPublicKeyFromPem(String publicKeyPath) throws Exception {
        String pem = new String(Files.readAllBytes(Paths.get(publicKeyPath))); 
        pem = pem.replace("-----BEGIN PUBLIC KEY-----", "")
                 .replace("-----END PUBLIC KEY-----", "")
                 .replaceAll("\\s", "");  
        byte[] der = Base64.getDecoder().decode(pem);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    public static PrivateKey loadPrivateKeyFromPem(String privateKeyPath) throws Exception {
        String pem = new String(Files.readAllBytes(Paths.get(privateKeyPath)));
        pem = pem.replace("-----BEGIN PRIVATE KEY-----", "")
                 .replace("-----END PRIVATE KEY-----", "")
                 .replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(pem);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    public static PublicKey loadPublicKeyFromBytes(byte[] derBytes) throws Exception {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(derBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    public static byte[] encryptWithPublicKey(String plaintext, PublicKey publicKey) throws Exception {
        var cipher = javax.crypto.Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(plaintext.getBytes("UTF-8"));
    }


    public static String decryptWithPrivateKey(byte[] ciphertext, PrivateKey privateKey) throws Exception {
        var cipher = javax.crypto.Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, privateKey);
        byte[] result = cipher.doFinal(ciphertext);
        return new String(result, "UTF-8");
    }
    

    public static SecretKey generateAesKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256); // 256-bit güvenlik
        return keyGen.generateKey();
    }


    public static byte[] encryptWithAes(byte[] plainData, SecretKey key) throws Exception {
        var cipher = javax.crypto.Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plainData);
    }


    public static byte[] decryptWithAes(byte[] cipherData, SecretKey key) throws Exception {
        var cipher = javax.crypto.Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(cipherData);
    }


    public static void main(String[] args) {
        try {
            //test için
            generateRsaKeyPair("public.pem", "private.pem");
            System.out.println("Generated public.pem and private.pem");


            PublicKey pubKey = loadPublicKeyFromPem("public.pem");
            String message = "Hello from Java RSA!";
            byte[] cipherBytes = encryptWithPublicKey(message, pubKey);
            System.out.println("Encrypted bytes length: " + cipherBytes.length);

            PrivateKey privKey = loadPrivateKeyFromPem("private.pem");
            String decrypted = decryptWithPrivateKey(cipherBytes, privKey);
            System.out.println("Decrypted text: " + decrypted);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
