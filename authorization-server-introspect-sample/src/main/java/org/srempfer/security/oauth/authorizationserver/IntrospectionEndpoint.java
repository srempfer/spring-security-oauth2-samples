package org.srempfer.security.oauth.authorizationserver;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.error.DefaultWebResponseExceptionTranslator;
import org.springframework.security.oauth2.provider.error.WebResponseExceptionTranslator;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IntrospectionEndpoint {

	private final ClientDetailsService clientDetailsService;
	private final TokenStore tokenStore;
	private final WebResponseExceptionTranslator<OAuth2Exception> exceptionTranslator;

	public IntrospectionEndpoint(ClientDetailsService clientDetailsService, TokenStore tokenStore) {
		this.clientDetailsService = clientDetailsService;
		this.tokenStore = tokenStore;
		this.exceptionTranslator = new DefaultWebResponseExceptionTranslator();
	}

	@PostMapping(path = "/oauth/introspect", produces = MediaType.APPLICATION_JSON_VALUE)
	public Map<String, Object> introspect(@RequestHeader("Authorization") String authorizationHeader,
			@RequestParam Map<String, String> body) {

		ClientDetails providedClientDetails = fromBasicAuthHeader(authorizationHeader);
		if (providedClientDetails == null) {
			throw new InvalidClientException("Bad client credentials");
		}

		ClientDetails clientDetails = null;
		try {
			clientDetails = clientDetailsService.loadClientByClientId(providedClientDetails.getClientId());
		} catch(NoSuchClientException e) {
			throw new InvalidClientException("Bad client credentials");
		}

		if (!StringUtils.equals(providedClientDetails.getClientSecret(), clientDetails.getClientSecret())) {
			throw new InvalidClientException("Bad client credentials");
		}

		String token = body.get("token");
		if (token == null) {
			return Map.of("active", Boolean.FALSE);
		}

		OAuth2AccessToken oAuth2AccessToken = tokenStore.readAccessToken(token);
		if (oAuth2AccessToken == null) {
			return Map.of("active", Boolean.FALSE);
		}

		Map<String, Object> result = new HashMap<>();
		result.put("active", !oAuth2AccessToken.isExpired());
		result.put("scope", StringUtils.join(oAuth2AccessToken.getScope(), " "));
		result.put("client_id", clientDetails.getClientId());
		result.put("exp", oAuth2AccessToken.getExpiration().getTime());

		OAuth2Authentication oAuth2Authentication = tokenStore.readAuthentication(oAuth2AccessToken);
		if (oAuth2Authentication != null) {
			String name = oAuth2Authentication.getUserAuthentication().getName();
			result.put("username", name);
		}

		return result;
	}

	@ExceptionHandler(InvalidClientException.class)
	public ResponseEntity<OAuth2Exception> handleException(Exception e) throws Exception {
		return exceptionTranslator.translate(e);
	}

	public static ClientDetails fromBasicAuthHeader(String header) {
		if (header == null) {
			return null;
		}

		header = header.trim();
		if (!StringUtils.startsWithIgnoreCase(header, "Basic")) {
			return null;
		}

		byte[] base64Token = header.substring(6).getBytes(StandardCharsets.UTF_8);
		byte[] decoded;
		try {
			decoded = Base64.getDecoder().decode(base64Token);
		}
		catch (IllegalArgumentException e) {
			throw new BadCredentialsException("Failed to decode basic authentication token");
		}

		String token = new String(decoded, StandardCharsets.UTF_8);

		int delim = token.indexOf(":");

		if (delim == -1) {
			throw new BadCredentialsException("Invalid basic authentication token");
		}

		BaseClientDetails client = new BaseClientDetails();
		client.setClientId(token.substring(0, delim));
		client.setClientSecret(token.substring(delim + 1));

		return client;
	}
}
