<?php

namespace Tokenly\AccountsClient;

use Exception;
use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Exception\BadResponseException;
use GuzzleHttp\Psr7\Request;

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
	
	
    protected function fetchFromAPI($method, $path, $parameters=[]) {
        $url = $this->api_url.'/api/v1/'.ltrim($path, '/');

        $client = new GuzzleClient(['http_errors' => true]);

        $headers = [];
        if ($method == 'GET') {
            $url .= '?'.http_build_query($parameters);
            $body = null;
        } else {
            $data = ['body' => $parameters];
            $headers['Content-Type'] = 'application/json';
            $body = json_encode($parameters);
        }
        $request = new Request($method, $url, $headers, $body);

        // send request
        try {
            $response = $client->send($request);
        } catch (BadResponseException $e) {
            if ($response = $e->getResponse()) {
                // interpret the response and error message
                $code = $response->getStatusCode();

                try {
                    $json = json_decode($response->getBody(), true);
                } catch (Exception $parse_json_exception) {
                    // could not parse json
                    $json = null;
                }

                if ($json and isset($json['error'])) {
                    $auth_exception = new Exception($json['error'], $code);
                    throw $auth_exception;
                }
            }

            // if no response, then just throw the original exception
            throw $e;
        }

        $json = json_decode($response->getBody(), true);
        if (!is_array($json)) { throw new Exception("Unexpected response", 1); }

        if ($json and isset($json['error'])) {
            $auth_exception = new Exception($json['error'], $response->getStatusCode());
            throw $auth_exception;
        }

        return $json;
    }
	
}
