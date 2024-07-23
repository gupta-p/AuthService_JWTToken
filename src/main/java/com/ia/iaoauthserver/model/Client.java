package com.ia.iaoauthserver.model;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jdk.jfr.Timestamp;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name="client")
public class Client {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;
	private String clientId;
	@Timestamp
	private Instant clientIdIssuedAt;

	private String clientSecret;

	@Timestamp
	private Instant clientSecretExpiresAt;
	private String clientName;
	private String clientAuthenticationMethods;
	private String authorizationGrantTypes;

	private String scopes;
	private String clientSettings;
	//Seconds
	private Long tokenSettingsAccessToken;
	//Seconds
	private Long tokenSettingsRefreshToken;
	private String expireZone;
	private String issuedZone;

}