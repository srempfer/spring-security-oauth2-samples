package org.srempfer.security.oauth.client;

import java.security.Principal;

import org.apache.commons.lang3.StringUtils;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
public class ClientOauth2SampleApplication {

	public static void main(String[] args) {
		SpringApplication.run(ClientOauth2SampleApplication.class, args);
	}

	@RestController
	public class Controller {

		@GetMapping("/")
		public String index(@AuthenticationPrincipal Principal principal) {
			if (principal != null) {
				return "Hello '" + principal.getName() + "' - welcome to OAuth2 Client Sample";
			} else {
				return "Welcome to OAuth2 Client Sample";
			}
		}

		@GetMapping("/home")
		public String home(@AuthenticationPrincipal OAuth2User principal) {
			return "Home of user: " + principal.getName() + " with authorities: "
					+ StringUtils.join(principal.getAuthorities());
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
				.oauth2Login();
		}

	}

}
