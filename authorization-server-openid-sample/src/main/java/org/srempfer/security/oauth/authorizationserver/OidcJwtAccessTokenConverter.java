package org.srempfer.security.oauth.authorizationserver;


import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;

import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaSigner;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.util.JsonParser;
import org.springframework.security.oauth2.common.util.JsonParserFactory;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

/**
 * Custom {@link JwtAccessTokenConverter} which do stuff required for OIDC.
 * <ul>
 *     <li>It adds the "kid" header to the JWT header section.</li>
 *     <li>It generates the Id Token</li>
 * </ul>
 */
public class OidcJwtAccessTokenConverter extends JwtAccessTokenConverter {

	public static final String KID = "default-key-id";

	private final JsonParser objectMapper = JsonParserFactory.create();
	private final Map<String, String> customHeaders;
	private final ServerProperties serverProperties;

	private RsaSigner signer;

	public OidcJwtAccessTokenConverter(ServerProperties serverProperties) {
		super();
		this.customHeaders = Collections.singletonMap("kid", "default-key-id");
		this.serverProperties = serverProperties;
	}

	@Override
	public void setKeyPair(KeyPair keyPair) {
		super.setKeyPair(keyPair);
		this.signer = new RsaSigner((RSAPrivateKey) keyPair.getPrivate());
	}

	@Override
	protected String encode(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
		String content;
		try {
			content = this.objectMapper
					.formatMap(getAccessTokenConverter().convertAccessToken(accessToken, authentication));
		}
		catch (Exception e) {
			throw new IllegalStateException("Cannot convert access token to JSON", e);
		}
		return JwtHelper.encode(content, this.signer, this.customHeaders).getEncoded();
	}

	@Override
	public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
		OAuth2AccessToken oAuth2AccessToken = super.enhance(accessToken, authentication);

		if (!authentication.isClientOnly()) {
			OAuth2AccessToken idToken = createIdToken(oAuth2AccessToken, authentication);
			oAuth2AccessToken.getAdditionalInformation().put("id_token", encode(idToken, authentication));
		}

		return oAuth2AccessToken;
	}

	private OAuth2AccessToken createIdToken(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
		DefaultOAuth2AccessToken result = new DefaultOAuth2AccessToken(accessToken);
		result.setExpiration(accessToken.getExpiration());

		String username = authentication.getUserAuthentication().getName();

		String baseUrl = ServletUriComponentsBuilder.fromCurrentRequest()
				.replacePath(serverProperties.getServlet().getContextPath())
				.replaceQuery(null)
				.toUriString();

		OAuth2Request oAuth2Request = authentication.getOAuth2Request();
		String clientId = oAuth2Request.getClientId();
		String nonce = oAuth2Request.getRequestParameters().get("nonce");

		Map<String, Object> additionalInformation = new HashMap<>();
		additionalInformation.put("sub", username);
		additionalInformation.put("aud", clientId);
		additionalInformation.put("iss", baseUrl);
		additionalInformation.put("iat", System.currentTimeMillis() / 1000);

		if (StringUtils.isNoneBlank(nonce)) {
			additionalInformation.put("nonce", nonce);
		}

		result.setAdditionalInformation(additionalInformation);

		return result;
	}

}
