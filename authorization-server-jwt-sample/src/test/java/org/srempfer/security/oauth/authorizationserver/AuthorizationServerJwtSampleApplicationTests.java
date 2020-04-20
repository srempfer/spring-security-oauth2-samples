package org.srempfer.security.oauth.authorizationserver;

import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AuthorizationServerJwtSampleApplicationTests {

	@LocalServerPort
	private int port;

	@Autowired
	private TestRestTemplate restTemplate;

	@Test
	void contextLoads() {
	}

	@Test
	void verifyIndexPage() {
		ResponseEntity<String> responseEntity =
				restTemplate.getForEntity("http://localhost:" + port + "/", String.class);
		assertThat(responseEntity.getStatusCode()).
				isEqualTo(HttpStatus.OK);
		assertThat(responseEntity.getBody())
				.contains("Welcome to AuthorizationServer Sample with JWT configuration");
	}

	@Test
	void verifyHomePageRenderLoginPageIfNotAuthenticated() {
		ResponseEntity<String> responseEntity =
				restTemplate.getForEntity("http://localhost:" + port + "/home", String.class);
		assertThat(responseEntity.getStatusCode()).
				isEqualTo(HttpStatus.OK);
		assertThat(responseEntity.getBody())
				.contains("username", "password", "_csrf");

	}

	@Test
	void verifyAuthorizeEndpointRenderLoginPageIfNotAuthenticated() {
		ResponseEntity<String> responseEntity =
				restTemplate.getForEntity("http://localhost:" + port + "/oauth/authorize", String.class);
		assertThat(responseEntity.getStatusCode()).
				isEqualTo(HttpStatus.OK);
		assertThat(responseEntity.getBody())
				.contains("username", "password", "_csrf");
	}

}
