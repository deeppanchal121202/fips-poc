package com.example.fips.poc.dto;

public record EncryptResponse(
        String algorithm,
        String provider,
        String iv,
        String ciphertext
) {
}