package org.srempfer.security.oauth.authorizationserver;

import java.security.KeyPair;
import java.security.Principal;
import java.security.interfaces.RSAPublicKey;
import java.util.Optional;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.authserver.AuthorizationServerProperties;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@EnableWebSecurity
@EnableAuthorizationServer
@SpringBootApplication
public class AuthorizationServerOpenIdSampleApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthorizationServerOpenIdSampleApplication.class, args);
	}

	@RestController
	public class Controller {

		@GetMapping("/")
		public String index() {
			return "Welcome to AuthorizationServer Sample with OpenId Connect support";
		}

		@GetMapping("/home")
		public String home(@AuthenticationPrincipal Principal principal) {
			return "Home of user: " + principal.getName();
		}
	}

	@Bean
	public OidcTokenServices oidcTokenServices(JwtTokenStore jwtTokenStore) {
		OidcTokenServices services = new OidcTokenServices();
		services.setTokenStore(jwtTokenStore);
		return services;
	}

	@Bean
	public JwtTokenStore tokenStore(JwtAccessTokenConverter accessTokenConverter) {
		return new JwtTokenStore(accessTokenConverter);
	}

	/*
	 * Primary is required here because otherwise this error occur:
	 *
	 * Field configurers in org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerSecurityConfiguration required a single bean, but 2 were found:
	 *  - oidcJwtAccessTokenConverter: defined by method 'oidcJwtAccessTokenConverter' in org.srempfer.security.oauth.authorizationserver.AuthorizationServerOpenIdSampleApplication
	 *  - accessTokenConverter: defined by method 'accessTokenConverter' in class path resource [org/springframework/boot/autoconfigure/security/oauth2/authserver/AuthorizationServerTokenServicesConfiguration$JwtKeyStoreConfiguration.class]
	 */
	@Primary
	@Bean
	public JwtAccessTokenConverter oidcJwtAccessTokenConverter(ServerProperties serverProperties, AuthorizationServerProperties authorizationServerProperties) {
		OidcJwtAccessTokenConverter converter = new OidcJwtAccessTokenConverter(serverProperties);
		converter.setKeyPair(getJwtKeyStoreKeyPair(authorizationServerProperties));
		return converter;
	}

	@Bean
	public JWKSet jwkSet(AuthorizationServerProperties authorizationServerProperties) {
		KeyPair jwtKeyStoreKeyPair = getJwtKeyStoreKeyPair(authorizationServerProperties);
		RSAKey.Builder builder = new RSAKey.Builder((RSAPublicKey) jwtKeyStoreKeyPair.getPublic())
				.keyUse(KeyUse.SIGNATURE)
				.algorithm(JWSAlgorithm.RS256)
				.keyID(OidcJwtAccessTokenConverter.KID);
		return new JWKSet(builder.build());
	}

	private KeyPair getJwtKeyStoreKeyPair(AuthorizationServerProperties authorizationServerProperties) {
		AuthorizationServerProperties.Jwt jwtProperties = authorizationServerProperties.getJwt();
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

	// See also
	// https://docs.spring.io/spring-security-oauth2-boot/docs/current/reference/htmlsingle/#oauth2-boot-authorization-server-spring-security-oauth2-resource-server-jwk-set-uri
	@Order(101)
	@Configuration
	public class JwkSetEndpointConfiguration extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.requestMatchers()
					.mvcMatchers("/.well-known/jwks.json", "/.well-known/openid-configuration")
					.and()
				.authorizeRequests()
					.mvcMatchers("/.well-known/jwks.json", "/.well-known/openid-configuration").permitAll();
		}
	}

	@Order(102)
	@Configuration
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
