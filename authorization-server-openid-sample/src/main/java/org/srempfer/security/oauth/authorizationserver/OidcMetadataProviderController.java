package org.srempfer.security.oauth.authorizationserver;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;


/**
 * A controller to serve provider configuration information as defined by the <i>OpenID Connect Discovery 1.0</i> specification.
 *
 * <p>
 * <b>NOTE:</b> This is a partial implementation that only serves a small subset of the available provider configuration information.
 *
 * @see <a target="_blank" href="http://openid.net/specs/openid-connect-discovery-1_0.html">OpenID Connect Discovery 1.0</a>
 */
@RestController
public class OidcMetadataProviderController {

	private final ServerProperties serverProperties;
	private final BaseClientDetails baseClientDetails;

	public OidcMetadataProviderController(ServerProperties serverProperties, BaseClientDetails baseClientDetails) {
		this.serverProperties = serverProperties;
		this.baseClientDetails = baseClientDetails;
	}

	/**
	 * Return provider configuration information as defined by the <i>OpenID Connect Discovery 1.0</i> specification.
	 *
	 * @return the provider configuration
	 */
	@GetMapping("/.well-known/openid-configuration")
	public Map<String, Object> getMetadata() {

		String baseUrl = ServletUriComponentsBuilder.fromCurrentRequest()
				.replacePath(serverProperties.getServlet().getContextPath())
				.replaceQuery(null)
				.toUriString();

		Map<String, Object> metadata = new HashMap<>();
		metadata.put("issuer", baseUrl);
		metadata.put("authorization_endpoint", baseUrl + "/oauth/authorize");
		metadata.put("token_endpoint", baseUrl + "/oauth/token");
		metadata.put("userinfo_endpoint", baseUrl + "/userinfo");
		metadata.put("jwks_uri", baseUrl + "/.well-known/jwks.json");
		metadata.put("grant_types_supported", baseClientDetails.getAuthorizedGrantTypes());
		metadata.put("scopes_supported", baseClientDetails.getScope());
		metadata.put("subject_types_supported", Collections.singleton("public"));

		return metadata;
	}

}
