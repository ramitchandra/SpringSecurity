package com.security.springsecurity.Controller;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JwtSecurityController {
	
	private JwtEncoder jwtEncoder;
	
	public JwtSecurityController(JwtEncoder jwtEncoder) {
		this.jwtEncoder = jwtEncoder;
	}
	
	@PostMapping("/authenticate")
	public JwtResponce authentication (Authentication authentication) {
		return new JwtResponce(createToken(authentication));
	}
	
	private String createToken(Authentication authentication) {
		var claims = JwtClaimsSet.builder()
					.issuer("self")
					.issuedAt(Instant.now())
					.expiresAt(Instant.now().plusSeconds(60 * 15))
					.subject(authentication.getName())
					.claim("scope", createScope(authentication))
					.build();
		return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
	}

	private String createScope(Authentication authentication) {
		return authentication.getAuthorities().stream().map(x -> x.getAuthority()).collect(Collectors.joining(" "));
	}

	@GetMapping("/jwt/hello")
	public String getHello() {
		return "Hey!!! This API is secured";
	}
	
	@PostMapping("/jwt/addHello")
	public List<MessageObj> addHello(@RequestBody MessageObj message) {
		List<MessageObj> tempList = new ArrayList<>();
		tempList.add(message);
		return tempList;
	}

}
