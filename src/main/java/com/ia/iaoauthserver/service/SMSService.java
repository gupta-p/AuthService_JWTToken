package com.ia.iaoauthserver.service;

public interface SMSService {

    void sendOTP(String recipientPhoneNumber, String otp);
}
