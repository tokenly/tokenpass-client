<?php

namespace Tokenly\AccountsClient;

use Exception;
use Requests;
use Tokenly\AccountsClient\Exception\AccountsAPIException;

class AccountsAPI
{
	public $client_id = false;
	public $api_url = false;
	
	function __construct()
	{
		if(function_exists('env')){
			$this->client_id = env('TOKENLY_ACCOUNTS_CLIENT_ID');
			$this->api_url = env('TOKENLY_ACCOUNTS_PROVIDER_HOST');
		}
		else{
			if(defined('TOKENLY_ACCOUNTS_CLIENT_ID')){
				$this->client_id = TOKENLY_ACCOUNTS_CLIENT_ID;
			}
			if(defined('TOKENLY_ACCOUNTS_PROVIDER_HOST')){
				$this->api_url = TOKENLY_ACCOUNTS_PROVIDER_HOST;
			}
		}
	}
	
	public function checkTokenAccess($username, $rules = array())
	{
		$rules['client_id'] = $this->client_id;
		try{
			$call = $this->fetchFromAPI('GET', 'tca/check/'.$username, $rules);
		}
		catch(Exception $e){
			return false;
		}
		if(!isset($call['result'])){
			return false;
		}
		return $call['result'];
	}
	
	public function getPublicAddresses($username)
	{
		try{
			$call = $this->fetchFromAPI('GET', 'tca/addresses/'.$username, array('client_id' => $this->client_id, 'public' => 1));
		}
		catch(Exception $e){
			return false;
		}
		if(!isset($call['result'])){
			return false;
		}
		return $call['result'];
	}
	
	public function getAddresses($username)
	{
		try{
			$call = $this->fetchFromAPI('GET', 'tca/addresses/'.$username, array('client_id' => $this->client_id));
		}
		catch(Exception $e){
			return false;
		}
		if(!isset($call['result'])){
			return false;
		}
		return $call['result'];
	}
	
	public function checkAddressTokenAccess($address, $sig, $rules = array())
	{
		$body = $rules;
		$body['sig'] = $sig;
		try{
			$call = $this->fetchFromAPI('GET', 'tca/check-address/'.$address, $body);
		}
		catch(Exeption $e){
			return false;
		}
		if(!isset($call['result'])){
			return false;
		}
		return $call['result'];
	}
	
    public function login($username, $password)
    {
        $params['client_id'] = $this->client_id;
        $params['username'] = $username;
        $params['password'] = $password;
        $result = $this->fetchFromAPI('POST', 'login', $params);
        if (isset($result['error']) AND trim($result['error']) != ''){
            throw new \Exception($result['error']);
        }

        if (!isset($result['id'])){
            throw new \Exception('Unknown error logging in user');
        }

        return $result;
    }


	public function registerAccount($username, $password, $email, $name = '')
	{
		$params['client_id'] = $this->client_id;	
        $params['username'] = $username;
        $params['password'] = $password;
        $params['email'] = $email;

        $result = $this->fetchFromAPI('POST', 'register', $params);

        if(isset($result['error']) AND trim($result['error']) != ''){
            throw new \Exception($result['error']);
        }
        if(!isset($result['result'])){
            throw new \Exception('Unknown error registering user');
        }
        return $result['result'];
	}
	
	public function updateAccount($user_id, $token, $password, $data = array())
	{
		$params = $data;
		$params['client_id'] = $this->client_id;	
		$params['user_id'] = $user_id;
		$params['token'] = $token;
		$params['current_password'] = $password;
		$call = $this->fetchFromAPI('PATCH', 'update', $params);
		if(!isset($call['result'])){
			throw new \Exception('Unknown error updating user');
		}
		if(isset($call['error']) AND trim($call['error']) != ''){
			throw new \Exception($call['error']);
		}
		return true;
	}

    // ------------------------------------------------------------------------
	
    protected function fetchFromAPI($method, $path, $parameters=[]) {
        $url = $this->api_url.'/api/v1/'.ltrim($path, '/');
        $options = [];

        // build body
        if ($method == 'GET') {
            $body = $parameters;
        } else {
            $headers['Content-Type'] = 'application/json';
            $headers['Accept'] = 'application/json';
            if ($parameters) {
                $body = json_encode($parameters);
            } else {
                $body = null;
            }
        }


        // send request
        try {
            $response = Requests::request($url, $headers, $body, $method, $options);
        } catch (Exception $e) {
            throw $e;
        }

        // decode json
        try {
            $json = json_decode($response->body, true);
        } catch (Exception $parse_json_exception) {
            // could not parse json
            $json = null;
            throw new AccountsAPIException("Unexpected response", 1);
        }

        // look for errors
        $is_bad_status_code = ($response->status_code >= 400 AND $response->status_code <= 500);
        $error_message = null;
        $error_code = 1;
        if ($json) {
            // check for error
            if (isset($json['error'])) {
                $error_message = $json['error'];
            } else if (isset($json['errors'])) {
                $error_message = isset($json['message']) ? $json['message'] : (is_array($json['errors']) ? implode(", ", $json['errors']) : $json['errors']);
            }
        }
        if ($is_bad_status_code) {
            if ($error_message === null) {
                $error_message = "Received bad status code: {$response->status_code}";
            }
            $error_code = $response->status_code;
        }

        // for any errors, throw an exception
        if ($error_message !== null) {
            throw new AccountsAPIException($error_message, $error_code);
        }

        return $json;
    }
	
}
