package com.ia.iaoauthserver;

import com.twilio.Twilio;
import com.twilio.rest.api.v2010.account.Message;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
//import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication
@EnableJpaRepositories("com.ia.iaoauthserver.repo")
public class IaoauthserverRopcApplication {

    public static void main(String[] args) {
        SpringApplication.run(IaoauthserverRopcApplication.class, args);
    }

}
