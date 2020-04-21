package org.srempfer.security.oauth.authorizationserver;

import org.apache.commons.lang3.StringUtils;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;

/**
 * Special {@link DefaultTokenServices} which is only there to remove existing tokens if a nonce is present in request.
 * See comment below.
 */
public class OidcTokenServices extends DefaultTokenServices {

	private TokenStore tokenStore;

	@Override
	public OAuth2AccessToken createAccessToken(OAuth2Authentication authentication) throws AuthenticationException {
		// check if there is a nonce in the request => remove existing token in that case
		// this is required because the nonce claim of the Id Token have to match to the nonce from the request
		OAuth2Request oAuth2Request = authentication.getOAuth2Request();
		String nonceOfRequest = oAuth2Request.getRequestParameters().get("nonce");
		if (StringUtils.isNoneBlank(nonceOfRequest)) {
			OAuth2AccessToken existingAccessToken = tokenStore.getAccessToken(authentication);
			if (existingAccessToken != null) {
				OAuth2RefreshToken refreshToken = existingAccessToken.getRefreshToken();
				if (refreshToken != null) {
					tokenStore.removeRefreshToken(refreshToken);
				}
				tokenStore.removeAccessToken(existingAccessToken);
			}
		}
		return super.createAccessToken(authentication);
	}

	@Override
	public void setTokenStore(TokenStore tokenStore) {
		super.setTokenStore(tokenStore);
		this.tokenStore = tokenStore;
	}
}
