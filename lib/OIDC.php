<?php

class SparkAPI_OIDC extends SparkAPI_OAuth implements SparkAPI_AuthInterface {
	
	protected $scope = null;
	
	function __construct($api_client_id, $api_client_secret, $redirect_uri, $scope = "openid", $access_token = null) {
		$this->scope = $scope;
		
		parent::__construct($api_client_id, $api_client_secret, $redirect_uri, $access_token = null);
	}
	
	function authentication_endpoint_uri($additional_params = array()) {
		$params = array(
			"client_id"	=> $this->api_client_id,
			"scope"		=> $this->scope,
			"response_type"	=> "code",
			"redirect_uri"	=> $this->oauth_redirect_uri
		);
		
		return $this->authentication_host() . "openid/authorize?" . http_build_query(array_merge($params, $additional_params));
	}
	
	function is_auth_request($request) {
		return ($request['uri'] == '/openid/token') ? true : false;
	}
	
	function sign_request($request) {
		if ($request['uri'] != "/openid/token") {
			$this->SetHeader('Authorization', 'Bearer '. $this->last_token);	//Weird, but we bomb if this empty auth header is included on open id token exchanges
		}

		// reload headers into request
		$request['headers'] = $this->headers;
		$request['query_string'] = http_build_query($request['params']);
		$request['cacheable_query_string'] = $request['query_string'];

		return $request;

	}
	
	function Grant($code, $type = 'authorization_code') {
		$body = array(
			'client_id' => $this->api_client_id,
			'client_secret' => $this->api_client_secret,
		 	'grant_type' => $type,
			'redirect_uri' => $this->oauth_redirect_uri
		);
		
		if ($type == 'authorization_code') {
			$body['code'] = $code;
		}
		if ($type == 'refresh_token') {
			$body['refresh_token'] = $code;
		}
		
		$response = $this->MakeAPICall("POST", "openid/token", '0s', array(), json_encode($body) );
		
		if ($response['success'] == true) {
			$this->SetAccessToken( $response['results']['access_token'] );
			$this->SetRefreshToken( $response['results']['refresh_token'] );
			
			if ( is_callable($this->access_change_callback) ) {
				call_user_func($this->access_change_callback, 'oauth', array('access_token' => $this->oauth_access_token, 'refresh_token' => $this->oauth_refresh_token) );
			}
			
			return true;
		}
		else {
			return false;
		}
		
	}
}
