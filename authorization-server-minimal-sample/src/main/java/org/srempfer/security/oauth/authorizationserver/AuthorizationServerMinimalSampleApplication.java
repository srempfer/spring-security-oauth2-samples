package org.srempfer.security.oauth.authorizationserver;

import java.security.Principal;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@EnableAuthorizationServer
@SpringBootApplication
public class AuthorizationServerMinimalSampleApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthorizationServerMinimalSampleApplication.class, args);
	}

	@RestController
	public class Controller {

		@GetMapping("/")
		public String index() {
			return "Welcome to AuthorizationServer Sample with minimal configuration";
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
					.antMatchers("/").permitAll()
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