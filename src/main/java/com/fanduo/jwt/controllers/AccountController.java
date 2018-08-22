package com.fanduo.jwt.controllers;

import com.fanduo.jwt.models.LoginRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/rest")
public class AccountController {

	@RequestMapping(path = "/v1/account", method = RequestMethod.POST)
	public ResponseEntity<String> doPost(
			@RequestBody LoginRequest request
			)
	{
		return new ResponseEntity<String>("", HttpStatus.OK);
	}

	@RequestMapping(path = "/v1/account", method = RequestMethod.GET)
	public ResponseEntity<String> doGet(@RequestHeader("Authorization") String bearer)
	{
		return new ResponseEntity<String>("", HttpStatus.OK);
	}
}
