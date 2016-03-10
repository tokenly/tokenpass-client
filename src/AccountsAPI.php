<?php

namespace Tokenly\AccountsClient;

use Exception;
use Illuminate\Http\Request;
use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Exception\RequestException;

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
	
	public function registerAccount($username, $password, $email, $name = '')
	{
		$params['client_id'] = $this->client_id;	
		$params['username'] = $username;
		$params['password'] = $password;
		$params['email'] = $email;
		$params['name'] = $name;	
		$call = $this->fetchFromAPI('POST', 'register', $params);
		if(!isset($call['result'])){
			throw new \Exception('Unknown error registering user');
		}
		if(isset($call['error']) AND trim($call['error']) != ''){
			throw new \Exception($call['error']);
		}
		return $call['result'];
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
        $api_path = $this->api_url.'/api/v1/'.ltrim($path, '/');

        $client = new GuzzleClient(['base_url' => $api_path]);

        if ($method == 'GET') {
            $data = ['query' => $parameters];

        } else {
            $data = ['body' => $parameters];
        }
        $request = $client->createRequest($method, $api_path, $data);

        // send request
        try {
            $response = $client->send($request);
        } catch (RequestException $e) {
            if ($response = $e->getResponse()) {
                // interpret the response and error message
                $code = $response->getStatusCode();

                try {
                    $json = $response->json();
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

        $json = $response->json();
        if (!is_array($json)) { throw new Exception("Unexpected response", 1); }

        if ($json and isset($json['error'])) {
            $auth_exception = new Exception($json['error'], $response->getStatusCode());
            throw $auth_exception;
        }

        return $json;
    }
	
}
