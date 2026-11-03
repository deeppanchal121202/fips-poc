package com.example.fips.poc;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

import java.security.Security;

@SpringBootApplication
public class FipsPocApplication {

	public static void main(String[] args) {
		if (Security.getProvider("BCFIPS") == null) {
			Security.insertProviderAt(
					new BouncyCastleFipsProvider(),
					1
			);
		}
		SpringApplication.run(FipsPocApplication.class, args);
	}

}
