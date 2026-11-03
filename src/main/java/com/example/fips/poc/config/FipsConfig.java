package com.example.fips.poc.config;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.fips.FipsStatus;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.springframework.context.annotation.Configuration;

import java.security.Security;

@Configuration
public class FipsConfig {

    public FipsConfig() {

        if (Security.getProvider("BCFIPS") == null) {
            Security.addProvider(
                    new BouncyCastleFipsProvider(
                            "C:DEFRND[HmacSHA512];ENABLE{ALL};"
                    )
            );
        }

        if (!FipsStatus.isReady()) {
            throw new IllegalStateException(
                    "BCFIPS module failed startup/self-test"
            );
        }

        if (!CryptoServicesRegistrar.isInApprovedOnlyMode()) {
            throw new IllegalStateException(
                    "BCFIPS is not running in approved-only mode"
            );
        }

        System.out.println("=================================");
        System.out.println("BCFIPS STATUS");
        System.out.println("=================================");

        System.out.println(
                "FIPS Ready       : " + FipsStatus.isReady()
        );

        System.out.println(
                "Approved Only    : "
                        + CryptoServicesRegistrar.isInApprovedOnlyMode()
        );

        System.out.println(
                "Provider         : "
                        + Security.getProvider("BCFIPS")
        );

        System.out.println("=================================");
    }
}