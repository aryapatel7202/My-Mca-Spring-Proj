package com.pcbuilder.pcbuilder;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@EnableScheduling
@SpringBootApplication
public class PcbuilderApplication {

	public static void main(String[] args) {
		SpringApplication.run(PcbuilderApplication.class, args);
	}

}
