package org.srempfer.security.oauth.authorizationserver;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.apache.commons.lang3.StringUtils;

import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeTokenGranter;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Extended {@link AuthorizationCodeTokenGranter} which verifies also PKCE (RFC 7636) related stuff.
 */
public class PkceAuthorizationCodeTokenGranter extends AuthorizationCodeTokenGranter {

    /**
     * Constructor.
     *
     * @param tokenServices the token services to use
     * @param authorizationCodeServices the authorization code services to use
     * @param clientDetailsService the client details service to use
     * @param requestFactory the request factory to use
     */
    public PkceAuthorizationCodeTokenGranter( AuthorizationServerTokenServices tokenServices,
        AuthorizationCodeServices authorizationCodeServices, ClientDetailsService clientDetailsService, OAuth2RequestFactory requestFactory ) {
        super ( tokenServices, authorizationCodeServices, clientDetailsService, requestFactory );
    }

    @Override
    protected OAuth2Authentication getOAuth2Authentication ( ClientDetails client, TokenRequest tokenRequest ) {
        // filter out the code challenge related parameters because getOAuth2Authentication() merge the
        // saved request parameters and the token request parameters
        //
        // only for safety because the PkceOAuth2RequestValidator already checks an reject token request which contains
        // code challenge related parameters
        Map<String, String> filteredParameters = filterCodeChallengeRelatedParameters ( tokenRequest );
        tokenRequest.setRequestParameters ( filteredParameters );
        OAuth2Authentication oAuth2Authentication = super.getOAuth2Authentication ( client, tokenRequest );

        // use the merged parameters to get the saved code challenge parameters and the code verifier of the token request
        Map<String, String> requestParameters = oAuth2Authentication.getOAuth2Request ().getRequestParameters ();
        String codeChallenge = requestParameters.get ( "code_challenge" );
        String codeChallengeMethod = requestParameters.get ( "code_challenge_method" );
        String codeVerifier = requestParameters.get ( "code_verifier" );

        if ( StringUtils.isNoneBlank ( codeChallenge )
            && !verifyCodeChallenge ( codeChallenge, codeChallengeMethod, codeVerifier ) ) {
            throw new InvalidGrantException( "Invalid code verifier: " + codeVerifier );
        }

        return oAuth2Authentication;
    }

    private Map<String, String> filterCodeChallengeRelatedParameters ( TokenRequest tokenRequest ) {
        Map<String, String> filteredParameters = new HashMap<String, String>();

        Set<Map.Entry<String, String>> entries = tokenRequest.getRequestParameters ().entrySet ();
        for ( Map.Entry<String, String> entry : entries ) {
            String key = entry.getKey ();
            if ( StringUtils.equalsAnyIgnoreCase ( key, "code_challenge", "code_challenge_method" ) ) {
                continue;
            }
            filteredParameters.put ( key, entry.getValue () );
        }
        return filteredParameters;
    }

    private boolean verifyCodeChallenge ( String codeChallenge, String codeChallengeMethod, String codeVerifier ) {
        if ( StringUtils.equalsAnyIgnoreCase ( codeChallengeMethod, null, "", "plain" ) ) {
            return StringUtils.equals ( codeChallenge, codeVerifier );
        } else {
            String hashedCodeVerifier = hashCodeVerifier ( codeVerifier );
            return MessageDigest.isEqual (
                codeChallenge.getBytes ( UTF_8 ),
                hashedCodeVerifier.getBytes ( UTF_8 ) );
        }
    }

    private String hashCodeVerifier ( String codeVerifier ) {
        try {
            final MessageDigest digest = MessageDigest.getInstance ( "SHA-256" );
            final byte[] hashedBytes = digest.digest ( codeVerifier.getBytes ( UTF_8 ) );
            return Base64.getUrlEncoder ().withoutPadding ().encodeToString ( hashedBytes );
        } catch ( NoSuchAlgorithmException e ) {
            throw new IllegalArgumentException( "Could not hash code verifier", e );
        }
    }

}
