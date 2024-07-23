package com.ia.iaoauthserver.service;

import com.twilio.Twilio;
import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class SMSServiceImpl implements SMSService {

    public static final String ACCOUNT_SID = "ACa29bed2d35afb5776babaaf9eedee431";
    public static final String AUTH_TOKEN = "21dde5e39b8ca96c6141d84403816bb9";
    @Value("${twilio.phone.number}")
    private String twilioPhoneNumber;


    // Method to send OTP via SMS
    @Override
    public void sendOTP(String recipientPhoneNumber, String otp) {
        try {
            Twilio.init(ACCOUNT_SID, AUTH_TOKEN);

            Message message = Message.creator(
                            new PhoneNumber(recipientPhoneNumber),
                            new PhoneNumber(twilioPhoneNumber),
                            "Your OTP is: " + otp)
                    .create();

            System.out.println("Message SID: " + message.getSid()); // Print SID for reference
        } catch (Exception e) {
            System.err.println("Error sending SMS: " + e.getMessage());
        }
    }
}
