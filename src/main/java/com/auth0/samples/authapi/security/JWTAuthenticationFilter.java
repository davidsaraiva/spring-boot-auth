package com.auth0.samples.authapi.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.auth0.samples.authapi.user.ApplicationUser;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import static com.auth0.samples.authapi.security.SecurityConfig.AUTHORIZATION_HEADER;
import static com.auth0.samples.authapi.security.SecurityConfig.TOKEN_PREFIX;

/**
 * Filter responsible for authenticating users
 */
public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	private final ObjectMapper objectMapper = new ObjectMapper();

	private final SecurityConfig securityConfig;

	private AuthenticationManager authenticationManager;

	public JWTAuthenticationFilter(AuthenticationManager authenticationManager, SecurityConfig securityConfig) {
		this.authenticationManager = authenticationManager;
		this.securityConfig = securityConfig;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest req, HttpServletResponse res)
			throws AuthenticationException {
		try {
			ApplicationUser creds = new ObjectMapper().readValue(req.getInputStream(), ApplicationUser.class);

			return authenticationManager.authenticate(
					new UsernamePasswordAuthenticationToken(creds.getUsername(), creds.getPassword(),
							new ArrayList<>()));
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest req, HttpServletResponse res, FilterChain chain,
			Authentication auth) throws IOException {

		String token = Jwts.builder()
				.setSubject(((User) auth.getPrincipal()).getUsername())
				.setExpiration(new Date(System.currentTimeMillis() + securityConfig.getExpirationTime()))
				.signWith(SignatureAlgorithm.HS512, securityConfig.getSecret().getBytes()).compact();
		res.addHeader(AUTHORIZATION_HEADER, TOKEN_PREFIX + token);
		res.getWriter().write(objectMapper.writeValueAsString(auth.getPrincipal()));
	}
}
