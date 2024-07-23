package com.ia.iaoauthserver.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.stereotype.Component;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.ArrayList;
import java.util.List;

@Component
public class CORSSettings {
	@Value("#{'${cors.allowed-origins:}'.split(',')}")
	private final List<String> origins = new ArrayList<>();
	@Value("#{'${cors.allowed-headers:}'.split(',')}")
	private final List<String> headers = new ArrayList<>();
	@Value("#{'${cors.allowed-methods:}'.split(',')}")
	private final List<String> methods = new ArrayList<>();
	public void applyCORSSettings(HttpSecurity http) throws Exception {
		http.cors(c -> {
			CorsConfigurationSource source = s -> {
				CorsConfiguration cors = new CorsConfiguration();
				cors.setAllowCredentials(true);
				cors.setAllowedHeaders(headers);
				cors.setAllowedMethods(methods);
				cors.setAllowedOrigins(origins);
				return cors;
			};
			c.configurationSource(source);
		});
	}
}
