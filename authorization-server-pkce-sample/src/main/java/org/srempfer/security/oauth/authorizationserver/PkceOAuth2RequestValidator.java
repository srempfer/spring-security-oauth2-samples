package org.srempfer.security.oauth.authorizationserver;

import java.util.Map;

import org.apache.commons.lang3.StringUtils;

import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestValidator;

/**
 * Extended {@link DefaultOAuth2RequestValidator} which validates also PKCE (RFC 7636) related stuff.
 */
public class PkceOAuth2RequestValidator extends DefaultOAuth2RequestValidator {

    @Override
    public void validateScope ( AuthorizationRequest authorizationRequest, ClientDetails client ) throws InvalidScopeException {
        super.validateScope ( authorizationRequest, client );

        Map<String, String> requestParameters = authorizationRequest.getRequestParameters ();
        String codeChallenge = requestParameters.get ( "code_challenge" );
        if ( isPublicClient ( client ) && StringUtils.isBlank ( codeChallenge ) ) {
            throw new InvalidRequestException( "Code challenge required." );
        }

        String codeChallengeMethod = requestParameters.get ( "code_challenge_method" );
        if ( !isValidateChallengeMethod ( codeChallengeMethod ) ) {
            throw new InvalidRequestException( "Code challenge method '" + codeChallengeMethod + "' is unsupported." );
        }
    }

    @Override
    public void validateScope ( TokenRequest tokenRequest, ClientDetails client ) throws InvalidScopeException {
        super.validateScope ( tokenRequest, client );

        Map<String, String> requestParameters = tokenRequest.getRequestParameters ();

        String codeVerifier = requestParameters.get ( "code_verifier" );
        if ( isPublicClient ( client ) && StringUtils.isBlank ( codeVerifier ) ) {
            throw new InvalidRequestException( "Code verifier required." );
        }

        String codeChallenge = requestParameters.get ( "code_challenge" );
        if ( StringUtils.isNotBlank ( codeChallenge ) ) {
            throw new InvalidRequestException( "Code challenge not allowed for token request." );
        }

        String codeChallengeMethod = requestParameters.get ( "code_challenge_method" );
        if ( StringUtils.isNotBlank ( codeChallengeMethod ) ) {
            throw new InvalidRequestException( "Code challenge method not allowed for token request." );
        }
    }

    private boolean isValidateChallengeMethod ( String codeChallengeMethod ) {
        return StringUtils.equalsAnyIgnoreCase ( codeChallengeMethod, null, "", "plain", "S256" );
    }

    private boolean isPublicClient ( ClientDetails client ) {
        return !client.isSecretRequired ();
    }
}
