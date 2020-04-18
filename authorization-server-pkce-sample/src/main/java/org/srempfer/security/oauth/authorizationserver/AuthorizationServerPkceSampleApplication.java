package org.srempfer.security.oauth.authorizationserver;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.authserver.AuthorizationServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.builders.InMemoryClientDetailsServiceBuilder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.client.ClientCredentialsTokenGranter;
import org.springframework.security.oauth2.provider.implicit.ImplicitTokenGranter;
import org.springframework.security.oauth2.provider.refresh.RefreshTokenGranter;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@EnableAuthorizationServer
@SpringBootApplication
public class AuthorizationServerPkceSampleApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthorizationServerPkceSampleApplication.class, args);
	}

	@Bean
	public TokenStore tokenStore () {
		return new InMemoryTokenStore();
	}

	@EnableConfigurationProperties(AuthorizationServerProperties.class)
	@Configuration
	public class AuthorizationServerConfig {

		private final AuthorizationServerProperties properties;
		private final TokenStore tokenStore;

		public AuthorizationServerConfig(AuthorizationServerProperties properties, TokenStore tokenStore) {
			this.properties = properties;
			this.tokenStore = tokenStore;
		}

		@Bean
		public AuthorizationServerConfigurer authorizationServerConfigurer() {
			return new AuthorizationServerConfigurerAdapter() {

				@Override
				public void configure(AuthorizationServerSecurityConfigurer authorizationServerSecurityConfigurer) throws Exception {

					authorizationServerSecurityConfigurer.allowFormAuthenticationForClients();

					//////////////////////////
					// copied from default OAuth2AuthorizationServerConfiguration
					// org.springframework.boot.autoconfigure.security.oauth2.authserver.OAuth2AuthorizationServerConfiguration
					//  .configure(org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer)
                    //
					authorizationServerSecurityConfigurer.passwordEncoder(NoOpPasswordEncoder.getInstance());
					if (properties.getCheckTokenAccess() != null) {
						authorizationServerSecurityConfigurer.checkTokenAccess(properties.getCheckTokenAccess());
					}

					if (properties.getTokenKeyAccess() != null) {
						authorizationServerSecurityConfigurer.tokenKeyAccess(properties.getTokenKeyAccess());
					}

					if (properties.getRealm() != null) {
						authorizationServerSecurityConfigurer.realm(properties.getRealm());
					}
					//
					//////////////////////////
				}

				@Override
				public void configure(ClientDetailsServiceConfigurer clientDetailsServiceConfigurer) throws Exception {
					InMemoryClientDetailsServiceBuilder inMemoryBuilder = clientDetailsServiceConfigurer.inMemory();
					inMemoryBuilder
							.withClient("private-client")
							.secret("secret")
							.redirectUris(new String[] {"http://localhost:9091/login/oauth2/code/sample-private-client-pkce"})
							.scopes ( new String[] {"private-client-scope-pkce"} )
							.autoApprove(new String[] {"private-client-scope-pkce"})
							.authorizedGrantTypes(new String[] {"authorization_code","refresh_token"});

					inMemoryBuilder
							.withClient("public-client")
							.secret(null)
							.redirectUris(new String[] {"http://localhost:9091/login/oauth2/code/sample-public-client-pkce"})
							.scopes ( new String[] {"public-client-scope-pkce"} )
							.autoApprove(new String[] {"public-client-scope-pkce"})
							.authorizedGrantTypes(new String[] {"authorization_code"});
				}

				@Override
				public void configure(AuthorizationServerEndpointsConfigurer authorizationServerEndpointsConfigurer) {

					authorizationServerEndpointsConfigurer.tokenStore(tokenStore);

					////////////////////////////////////////////////////////////////////////////////
					//
					// Required for RFC 7636: Proof Key for Code Exchange (PKCE, pronounced "pixy")
					//
					// Most is copied from org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer.tokenGranter()
					// only the AuthorizationCodeTokenGranter is replaced with PkceAuthorizationCodeTokenGranter
					// and the ResourceOwnerPasswordTokenGranter is missing
					//
					authorizationServerEndpointsConfigurer.requestValidator ( new PkceOAuth2RequestValidator () );

					List<TokenGranter> tokenGranters = new ArrayList<>();
					tokenGranters.add ( new PkceAuthorizationCodeTokenGranter (
							authorizationServerEndpointsConfigurer.getTokenServices(),
							authorizationServerEndpointsConfigurer.getAuthorizationCodeServices (),
							authorizationServerEndpointsConfigurer.getClientDetailsService(),
							authorizationServerEndpointsConfigurer.getOAuth2RequestFactory() ) );
					tokenGranters.add ( new RefreshTokenGranter(
							authorizationServerEndpointsConfigurer.getTokenServices(),
							authorizationServerEndpointsConfigurer.getClientDetailsService(),
							authorizationServerEndpointsConfigurer.getOAuth2RequestFactory() ) );
					tokenGranters.add ( new ImplicitTokenGranter(
							authorizationServerEndpointsConfigurer.getTokenServices(),
							authorizationServerEndpointsConfigurer.getClientDetailsService(),
							authorizationServerEndpointsConfigurer.getOAuth2RequestFactory() ) );
					tokenGranters.add ( new ClientCredentialsTokenGranter(
							authorizationServerEndpointsConfigurer.getTokenServices(),
							authorizationServerEndpointsConfigurer.getClientDetailsService(),
							authorizationServerEndpointsConfigurer.getOAuth2RequestFactory() ) );

					authorizationServerEndpointsConfigurer.tokenGranter ( new CompositeTokenGranter( tokenGranters ) );
					//
					///////////////////////////////////////////////////////////////////////////////

				}
			};
		}
	}

	@RestController
	public class Controller {

		@GetMapping("/")
		public String index() {
			return "Welcome to AuthorizationServer Sample with PKCE support";
		}

		@GetMapping("/home")
		public String home(@AuthenticationPrincipal Principal principal) {
			return "Home of user: " + principal.getName();
		}
	}

	@Configuration
	@EnableWebSecurity
	public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.authorizeRequests()
					.antMatchers("/", "/userinfo").permitAll()
					.anyRequest().authenticated()
					.and()
				.formLogin()
					.permitAll()
					.and()
				.logout()
					.permitAll();
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth.inMemoryAuthentication()
					.withUser("testuser").password("{noop}testpw").roles("USER");
		}

	}

}
