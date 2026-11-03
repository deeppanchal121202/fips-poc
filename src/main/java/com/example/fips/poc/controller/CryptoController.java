package com.example.fips.poc.controller;

import com.example.fips.poc.dto.DecryptRequest;
import com.example.fips.poc.dto.EncryptRequest;
import com.example.fips.poc.dto.EncryptResponse;
import com.example.fips.poc.service.CryptoService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/crypto")
public class CryptoController {

    private final CryptoService cryptoService;

    public CryptoController(CryptoService cryptoService) {
        this.cryptoService = cryptoService;
    }

    @PostMapping("/encrypt")
    public EncryptResponse encrypt(
            @RequestBody EncryptRequest request) {

        CryptoService.EncryptionResult result =
                cryptoService.encrypt(request.plaintext());

        return new EncryptResponse(
                "AES-256-GCM",
                result.provider(),
                result.iv(),
                result.ciphertext()
        );
    }

    @PostMapping("/decrypt")
    public String decrypt(
            @RequestBody DecryptRequest request) {

        return cryptoService.decrypt(
                request.iv(),
                request.ciphertext()
        );
    }
}