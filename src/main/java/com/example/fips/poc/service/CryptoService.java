package com.example.fips.poc.service;

import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;

@Service
public class CryptoService {

    private static final String PROVIDER = "BCFIPS";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";

//    private static final String PROVIDER = "BCFIPS";
    private static final String KEYSTORE_TYPE = "BCFKS";
    private static final String KEY_ALIAS = "aes-encryption-key";

    private final SecretKey aesKey;

    public CryptoService() {
        try {
            this.aesKey = loadOrCreateAesKey();
            System.out.println(this.aesKey);
        } catch (Exception ex) {
            throw new IllegalStateException(
                    "Unable to load or initialize FIPS AES key",
                    ex
            );
        }
    }

    private SecretKey loadOrCreateAesKey() throws Exception {

        // Read password from environment
        String password =
                System.getenv("BCFKS_STORE_PASSWORD");

        if (password == null || password.isBlank()) {
            throw new IllegalStateException(
                    "BCFKS_STORE_PASSWORD environment variable is required"
            );
        }

        char[] storePassword = password.toCharArray();

        // File location: ./keystore/encryption.bcfks
        Path keyStorePath = Paths.get(
                "keystore", "encryption.bcfks"
        ).toAbsolutePath();

        Files.createDirectories(keyStorePath.getParent());

        // Use the Bouncy Castle FIPS provider explicitly
        KeyStore keyStore =
                KeyStore.getInstance(KEYSTORE_TYPE, PROVIDER);

        // Load existing keystore or initialize a new one
        if (Files.exists(keyStorePath)) {
            try (InputStream input =
                         Files.newInputStream(keyStorePath)) {
                keyStore.load(input, storePassword);
            }
        } else {
            keyStore.load(null, storePassword);
        }

        // If the key already exists, reuse it
        if (keyStore.containsAlias(KEY_ALIAS)) {

            SecretKey existingKey = (SecretKey) keyStore.getKey(
                    KEY_ALIAS, storePassword
            );

            if (existingKey == null) {
                throw new IllegalStateException(
                        "AES key was not found in the keystore"
                );
            }

            return existingKey;
        }

        // Otherwise, generate the key only once
        SecureRandom secureRandom =
                SecureRandom.getInstance("DEFAULT", PROVIDER);

        KeyGenerator keyGenerator =
                KeyGenerator.getInstance("AES", PROVIDER);

        keyGenerator.init(256, secureRandom);

        SecretKey newKey = keyGenerator.generateKey();

        // Save the key in the protected keystore
        keyStore.setKeyEntry(
                KEY_ALIAS,
                newKey,
                storePassword,
                null
        );

        try (OutputStream output =
                     Files.newOutputStream(keyStorePath)) {
            keyStore.store(output, storePassword);
        }

        return newKey;
    }

    // Keep your existing encrypt() and decrypt() methods here.
    // Both must use this same aesKey instance.

//    private final SecretKey aesKey;
//
//    public CryptoService() {
//
//        try {
//
//            KeyGenerator keyGenerator =
//                    KeyGenerator.getInstance("AES", PROVIDER);
//
//            keyGenerator.init(256);
//
//            this.aesKey = keyGenerator.generateKey();
//
//        } catch (Exception ex) {
//            throw new IllegalStateException(
//                    "Unable to initialize FIPS AES key",
//                    ex
//            );
//        }
//    }

    public EncryptionResult encrypt(String plaintext) {

        try {
            SecureRandom secureRandom =
                    SecureRandom.getInstance("DEFAULT", PROVIDER);

            byte[] iv = new byte[12];
            secureRandom.nextBytes(iv);

            Cipher cipher =
                    Cipher.getInstance(
                            TRANSFORMATION,
                            PROVIDER
                    );

            GCMParameterSpec gcmSpec =
                    new GCMParameterSpec(128, iv);

            cipher.init(
                    Cipher.ENCRYPT_MODE,
                    aesKey,
                    gcmSpec
            );

            byte[] encrypted =
                    cipher.doFinal(
                            plaintext.getBytes(StandardCharsets.UTF_8)
                    );

            return new EncryptionResult(
                    Base64.getEncoder().encodeToString(iv),
                    Base64.getEncoder().encodeToString(encrypted),
                    cipher.getProvider().getName()
            );

        } catch (Exception ex) {
            throw new IllegalStateException(
                    "FIPS encryption failed",
                    ex
            );
        }
    }

    public String decrypt(
            String ivBase64,
            String ciphertextBase64) {

        try {

            byte[] iv =
                    Base64.getDecoder()
                            .decode(ivBase64);

            byte[] ciphertext =
                    Base64.getDecoder()
                            .decode(ciphertextBase64);

            Cipher cipher =
                    Cipher.getInstance(
                            TRANSFORMATION,
                            PROVIDER
                    );

            GCMParameterSpec gcmSpec =
                    new GCMParameterSpec(128, iv);

            cipher.init(
                    Cipher.DECRYPT_MODE,
                    aesKey,
                    gcmSpec
            );

            byte[] plaintext =
                    cipher.doFinal(ciphertext);

            return new String(
                    plaintext,
                    StandardCharsets.UTF_8
            );

        } catch (Exception ex) {
            throw new IllegalStateException(
                    "FIPS decryption failed",
                    ex
            );
        }
    }

    public record EncryptionResult(
            String iv,
            String ciphertext,
            String provider
    ) {
    }
}