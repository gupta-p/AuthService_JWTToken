package com.ia.iaoauthserver.repo;

import com.ia.iaoauthserver.model.OTPModel;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OTPRepo extends JpaRepository<OTPModel, String> {
    OTPModel findByUserName(String username);
}
