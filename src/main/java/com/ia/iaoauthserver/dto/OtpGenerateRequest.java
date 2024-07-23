package com.ia.iaoauthserver.dto;

import lombok.Data;

@Data
public class OtpGenerateRequest {
    private String username;
    private String phoneNumber;
}
