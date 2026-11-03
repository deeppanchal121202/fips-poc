package com.example.fips.poc.controller;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.fips.FipsStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Provider;
import java.security.Security;
import java.util.LinkedHashMap;
import java.util.Map;

@RestController
public class FipsController {

    @GetMapping("/api/fips/status")
    public Map<String, Object> status() {

        Map<String, Object> response = new LinkedHashMap<>();

        Provider provider = Security.getProvider("BCFIPS");

        response.put("providerPresent", provider != null);
        response.put(
                "providerName",
                provider != null ? provider.getName() : null
        );
        response.put(
                "providerVersion",
                provider != null ? provider.getVersionStr() : null
        );
        response.put(
                "fipsReady",
                FipsStatus.isReady()
        );
        response.put(
                "approvedOnly",
                CryptoServicesRegistrar.isInApprovedOnlyMode()
        );

        return response;
    }
}
