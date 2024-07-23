package com.ia.iaoauthserver.service;

import com.ia.iaoauthserver.model.OTPModel;
import com.ia.iaoauthserver.repo.OTPRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;

@Service
public class OTPServiceImpl implements OTPService{

    @Autowired
    OTPRepo otpRepo;

    @Autowired
    SMSService smsService;

    @Override
    public boolean validateOTP(String username) {
        OTPModel otpModel = otpRepo.findByUserName(username);
        if (otpModel != null) {
            if(LocalDateTime.now().isAfter(otpModel.getExpiredDateTime())) {
                return false;
            }
        }
        return true;
    }

    @Override
    public String generateOtp(String userName, String phoneNumber) {
        OTPModel otpModel = otpRepo.findByUserName(userName);
        if (otpModel == null) {
            otpModel = new OTPModel();
        }
        otpModel.setUserName(userName);
        otpModel.setCreateDateTime(LocalDateTime.now());
        int OTP = (int) (Math.random() * 9000) + 1000;
        otpModel.setOtp(OTP);
        otpModel.setExpiredDateTime(otpModel.getCreateDateTime().plus(1, ChronoUnit.MINUTES));
        smsService.sendOTP(phoneNumber, String.valueOf(OTP));
        otpRepo.save(otpModel);
        return "OTP sent to user: " + userName + " OTP: " + OTP;
    }
}
