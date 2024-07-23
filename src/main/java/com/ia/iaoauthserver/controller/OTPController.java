package com.ia.iaoauthserver.controller;

import com.ia.iaoauthserver.dto.OtpGenerateRequest;
import com.ia.iaoauthserver.service.OTPService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OTPController {
    @Autowired
    OTPService otpService;

    @RequestMapping(value = "/generate-otp", method = RequestMethod.POST)
    public String generateOTP(@RequestBody OtpGenerateRequest otpGenerateRequest) throws Exception {
        String otp = otpService.generateOtp(otpGenerateRequest.getUsername(), otpGenerateRequest.getPhoneNumber());
        return otp;
    }

}
