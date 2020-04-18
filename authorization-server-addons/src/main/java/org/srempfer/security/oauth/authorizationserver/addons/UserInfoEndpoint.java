package org.srempfer.security.oauth.authorizationserver.addons;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.http.MediaType;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserInfoEndpoint {

	private final TokenStore tokenStore;

	public UserInfoEndpoint(TokenStore tokenStore) {
		this.tokenStore = tokenStore;
	}

	@GetMapping(value = "/userinfo", produces = MediaType.APPLICATION_JSON_VALUE)
	public Map<String, Object> userinfo(@RequestHeader("Authorization") String authorizationHeader) {

		String token = extractTokenFromBearerAuthorizationHeader(authorizationHeader);
		if (token == null) {
			return Collections.emptyMap();
		}

		OAuth2Authentication authentication = tokenStore.readAuthentication(token);
		if (authentication == null) {
			return Collections.emptyMap();
		}

		Map<String, Object> result = new HashMap<>();
		String name = authentication.getUserAuthentication().getName();
		result.put("sub", name);

		Collection<? extends GrantedAuthority> grantedAuthorities = authentication.getAuthorities();
		Set<String> authorities = grantedAuthorities.stream()
				.map(grantedAuthority -> grantedAuthority.getAuthority())
				.collect(Collectors.toSet());

		result.put("authorities", authorities);

		return result;
	}

	public static String extractTokenFromBearerAuthorizationHeader(String header) {
		if (header == null) {
			return null;
		}
		header = header.trim();
		if (!StringUtils.startsWithIgnoreCase(header, "Bearer")) {
			return null;
		}
		return header.substring(7);
	}

}
