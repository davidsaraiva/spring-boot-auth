package com.auth0.samples.authapi.security;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import lombok.Getter;
import lombok.Setter;

@Configuration
@ConfigurationProperties(prefix = "security.token")
public class SecurityConfig {

	public static final String TOKEN_PREFIX = "Bearer ";

	public static final String AUTHORIZATION_HEADER = "Authorization";

	public static final String SIGN_UP_URL = "/users/sign-up";

	@Getter
	@Setter
	private long expirationTime;

	@Getter
	@Setter
	private String secret;

	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}
}
