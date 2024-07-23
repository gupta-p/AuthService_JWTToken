package com.ia.iaoauthserver.service;

public interface OTPService {
    boolean validateOTP(String username);

    String generateOtp(String username, String phoneNumber);
}
