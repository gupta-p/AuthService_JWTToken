package com.ia.iaoauthserver.dto;

import lombok.Data;

import java.time.Instant;

@Data
public class ClientDto {
    private String id;
    private String clientId;
    private Instant clientIdIssuedAt;
    private String clientSecret;
    private String clientSecretExpiresAt;
    private String clientName;
    private String[] clientAuthenticationMethods;
    private String[] authorizationGrantTypes;
    private String[] redirectUris;
    private String postLogoutURI;
    private String scopes;
    private String clientSettings;
    private Long tokenSettingsAccessToken;
    private Long tokenSettingsRefreshToken;
    private String clientIdIssuedAtString;
    private String clientAuthenticationMethodsString;
    private String authorizationGrantTypesString;
    private String redirectUrisString;
}