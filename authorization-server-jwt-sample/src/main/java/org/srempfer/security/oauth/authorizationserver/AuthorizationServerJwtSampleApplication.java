package org.srempfer.security.oauth.authorizationserver;

import java.security.Principal;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerSecurityConfiguration;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@EnableWebSecurity
@EnableAuthorizationServer
@SpringBootApplication
public class AuthorizationServerJwtSampleApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthorizationServerJwtSampleApplication.class, args);
	}

	@RestController
	public class Controller {

		@GetMapping("/")
		public String index() {
			return "Welcome to AuthorizationServer Sample with JWT configuration";
		}

		@GetMapping("/home")
		public String home(@AuthenticationPrincipal Principal principal) {
			return "Home of user: " + principal.getName();
		}
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
					.mvcMatchers("/.well-known/jwks.json")
					.and()
				.authorizeRequests()
					.mvcMatchers("/.well-known/jwks.json").permitAll();
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
