package org.srempfer.security.oauth.authorizationserver;

import java.security.KeyPair;
import java.security.Principal;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;
import java.util.Optional;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;

import org.springframework.boot.autoconfigure.security.oauth2.authserver.AuthorizationServerProperties;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.oauth2.provider.endpoint.FrameworkEndpoint;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

// see also
// https://docs.spring.io/spring-security-oauth2-boot/docs/current/reference/htmlsingle/#oauth2-boot-authorization-server-spring-security-oauth2-resource-server-jwk-set-uri
@FrameworkEndpoint
public class JwkSetEndpoint {
	private KeyPair keyPair;

	public JwkSetEndpoint(AuthorizationServerProperties authorizationServerProperties) {
		this.keyPair = getJwtKeyStoreKeyPair(authorizationServerProperties.getJwt());
	}

	@GetMapping("/.well-known/jwks.json")
	@ResponseBody
	public Map<String, Object> getKey(Principal principal) {
		RSAPublicKey publicKey = (RSAPublicKey) this.keyPair.getPublic();
		RSAKey key = new RSAKey.Builder(publicKey).build();
		return new JWKSet(key).toJSONObject();
	}

	private final KeyPair getJwtKeyStoreKeyPair(AuthorizationServerProperties.Jwt jwtProperties) {
		Assert.notNull(jwtProperties.getKeyStore(), "keyStore cannot be null");
		Assert.notNull(jwtProperties.getKeyStorePassword(), "keyStorePassword cannot be null");
		Assert.notNull(jwtProperties.getKeyAlias(), "keyAlias cannot be null");
		ResourceLoader resourceLoader = new DefaultResourceLoader();
		Resource keyStore = resourceLoader.getResource(jwtProperties.getKeyStore());
		char[] keyStorePassword = jwtProperties.getKeyStorePassword().toCharArray();
		KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(keyStore, keyStorePassword);

		String keyAlias = jwtProperties.getKeyAlias();
		char[] keyPassword = Optional.ofNullable(
				jwtProperties.getKeyPassword())
				.map(String::toCharArray).orElse(keyStorePassword);

		return keyStoreKeyFactory.getKeyPair(keyAlias, keyPassword);
	}
}
