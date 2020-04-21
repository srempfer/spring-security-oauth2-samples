package org.srempfer.security.oauth.authorizationserver;

import java.security.Principal;
import java.util.Map;

import com.nimbusds.jose.jwk.JWKSet;

import org.springframework.security.oauth2.provider.endpoint.FrameworkEndpoint;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

// se also
// https://docs.spring.io/spring-security-oauth2-boot/docs/current/reference/htmlsingle/#oauth2-boot-authorization-server-spring-security-oauth2-resource-server-jwk-set-uri
@FrameworkEndpoint
public class JwkSetEndpoint {

	private JWKSet jwkSet;

	public JwkSetEndpoint(JWKSet jwkSet) {
		this.jwkSet = jwkSet;
	}

	@GetMapping("/.well-known/jwks.json")
	@ResponseBody
	public Map<String, Object> getKey(Principal principal) {
		return jwkSet.toJSONObject();
	}
}
