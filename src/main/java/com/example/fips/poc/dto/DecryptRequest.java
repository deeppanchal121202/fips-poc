package com.example.fips.poc.dto;

public record DecryptRequest(
        String iv,
        String ciphertext
) {
}