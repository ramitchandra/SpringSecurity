package com.security.springsecurity.Controller;

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import jakarta.annotation.security.RolesAllowed;
import jakarta.servlet.http.HttpServletRequest;

@RestController
public class BasicSecurityController {
	
	@GetMapping("/csrf-token")
	public CsrfToken getCsrfToken(HttpServletRequest request) {
		return (CsrfToken) request.getAttribute("_csrf");
	}

	@GetMapping("/basic/{user}/hello")
	@PreAuthorize("hasRole('ADMIN') and #user == authentication.name")
	@PostAuthorize("returnObject.message == 'Hey admin !!! This API is secured'")
	@RolesAllowed({"ADMIN", "USER"}) // part of jsr250Enabled
	@Secured({"ROLE_ADMIN", "ROLE_USER"}) // part of securedEnabled
	public MessageObj getHello(@PathVariable String user) {
		return new MessageObj("Hey " + user + " !!! This API is secured");
	}
	
	@PostMapping("/basic/addHello")
	public List<MessageObj> addHello(@RequestBody MessageObj message) {
		List<MessageObj> tempList = new ArrayList<>();
		tempList.add(message);
		return tempList;
	}

}

record MessageObj(String message){}

record JwtResponce(String token) {}
