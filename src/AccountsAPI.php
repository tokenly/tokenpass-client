<?php

namespace Tokenly\AccountsClient;

use Exception;
use Illuminate\Http\Request;
use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Exception\RequestException;

class AccountsAPI
{
	
	public function checkTokenAccess($username, $rules = array())
	{
		$rules['client_id'] = env('TOKENLY_ACCOUNTS_CLIENT_ID');
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
			$call = $this->fetchFromAPI('GET', 'tca/addresses/'.$username, array('client_id' => env('TOKENLY_ACCOUNTS_CLIENT_ID')));
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
		$params['client_id'] = env('TOKENLY_ACCOUNTS_CLIENT_ID');	
		$params['username'] = $username;
		$params['password'] = $password;
		$params['email'] = $email;
		$params['name'] = $name;	
		try{
			$call = $this->fetchFromAPI('POST', 'register', $params);
		}
		catch(Exception $e){
			return false;
		}
		if(!isset($call['result'])){
			return false;
		}
		if(isset($call['error']) AND trim($call['error']) != ''){
			throw new \Exception($call['error']);
		}
		return $call['result'];
	}
	
	
    protected function fetchFromAPI($method, $path, $parameters=[]) {
        $api_path = env('TOKENLY_ACCOUNTS_PROVIDER_HOST').'/api/v1/'.ltrim($path, '/');

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
