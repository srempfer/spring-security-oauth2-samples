package org.srempfer.security.oauth.resourceserver;

import java.security.Principal;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
public class ResourceServerOpaqueSampleApplication {

	public static void main(String[] args) {
		SpringApplication.run(ResourceServerOpaqueSampleApplication.class, args);
	}

	@RestController
	public class ResourceController {

		@GetMapping("/")
		public String index(@AuthenticationPrincipal Principal principal) {
			return String.format("Hello '" + principal.getName()
					+ "' - welcome to OAuth2 Resource Server Sample with Opaque Token support", principal.getName());
		}

		@GetMapping("/greet")
		public String message() {
			return "Greetings from Resource Server with Opaque Token support";
		}

	}

	@Configuration
	@EnableWebSecurity
	public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.oauth2ResourceServer()
					.opaqueToken();
		}

	}

}
