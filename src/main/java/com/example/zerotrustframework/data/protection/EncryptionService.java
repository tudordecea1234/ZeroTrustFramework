package com.example.zerotrustframework.data.protection;

import jakarta.annotation.PostConstruct;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class EncryptionService {
    private final ProtectionProperties props;
    private SecretKeySpec secretKeySpec;
    private static final int GCM_TAG_LENGTH = 128;
    private static final int GCM_IV_LENGTH = 12;

    public EncryptionService(ProtectionProperties props) {
        this.props = props;
    }

    @PostConstruct
    public void initKey() {
        String keyBase64 = props.getEncryptionKey();
        if (keyBase64 == null || keyBase64.isEmpty()) {
            throw new IllegalArgumentException("Encryption key is not configured.");
        }
        byte[] decodedKey = Base64.getDecoder().decode(keyBase64);
        this.secretKeySpec = new SecretKeySpec(decodedKey, "AES");
    }

    public String encrypt(String plainText) {
        try {
            byte[] iv = new byte[GCM_IV_LENGTH];
            new SecureRandom().nextBytes(iv);

            Cipher cipher = Cipher.getInstance(props.getAlgorithm()); // ex. "AES/GCM/NoPadding"
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, spec);

            byte[] encrypted = cipher.doFinal(plainText.getBytes("UTF-8"));

            byte[] combined = new byte[iv.length + encrypted.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);

            return Base64.getEncoder().encodeToString(combined);
        } catch (Exception e) {
            //log with dedicated module!!
            throw new RuntimeException("Encryption failed: " + e.getMessage(), e);
        }
    }

    public String decrypt(String cipherBase64) {
        try {
            byte[] combined = Base64.getDecoder().decode(cipherBase64);
            byte[] iv = new byte[GCM_IV_LENGTH];
            byte[] encrypted = new byte[combined.length - GCM_IV_LENGTH];

            System.arraycopy(combined, 0, iv, 0, GCM_IV_LENGTH);
            System.arraycopy(combined, GCM_IV_LENGTH, encrypted, 0, encrypted.length);

            Cipher cipher = Cipher.getInstance(props.getAlgorithm());
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, spec);

            byte[] decrypted = cipher.doFinal(encrypted);
            return new String(decrypted, "UTF-8");
        } catch (Exception e) {
            //Log using dedicated module!!!!!
            throw new RuntimeException("Decryption failed: " + e.getMessage(), e);
        }
    }
}
