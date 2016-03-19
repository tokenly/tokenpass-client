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
            $this->client_id     = env('TOKENLY_ACCOUNTS_CLIENT_ID');
            $this->client_secret = env('TOKENLY_ACCOUNTS_CLIENT_SECRET');
            $this->api_url       = env('TOKENLY_ACCOUNTS_PROVIDER_HOST');
            $this->redirect_uri  = env('TOKENLY_ACCOUNTS_REDIRECT_URI');
		}
		else{
            $this->client_id     = (defined('TOKENLY_ACCOUNTS_CLIENT_ID')     ? constant('TOKENLY_ACCOUNTS_CLIENT_ID')     : null);
            $this->api_url       = (defined('TOKENLY_ACCOUNTS_PROVIDER_HOST') ? constant('TOKENLY_ACCOUNTS_PROVIDER_HOST') : null);
            $this->redirect_uri  = (defined('TOKENLY_ACCOUNTS_REDIRECT_URI')  ? constant('TOKENLY_ACCOUNTS_REDIRECT_URI')  : null);
            $this->client_secret = (defined('TOKENLY_ACCOUNTS_CLIENT_SECRET') ? constant('TOKENLY_ACCOUNTS_CLIENT_SECRET') : null);
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
    // oAuth

    public function registerAccount($username, $password, $email, $name = '')
    {
        $params = [];
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

    public function verifyLoginCredentials($username, $password) {
        $params['client_id'] = $this->client_id;
        $params['username']  = $username;
        $params['password']  = $password;

        $result = $this->fetchFromAPI('POST', 'login', $params);

        if (isset($result['error']) AND trim($result['error']) != ''){
            throw new \Exception($result['error']);
        }
 
        if (!isset($result['id'])) {
            throw new \Exception('Unknown error logging in user');
        }

        return $result;
    }

    public function getOAuthAuthorizationCodeWithCredentials($username, $password, $scopes)
    {
        $state = hash('sha256', microtime().':'.mt_rand());
        $scope = join(',', $scopes);

        $get_parameters = [];
        $get_parameters['client_id']     = $this->client_id;
        $get_parameters['state']         = $state;
        $get_parameters['redirect_uri']  = $this->redirect_uri;
        $get_parameters['scope']         = $scope;
        $get_parameters['response_type'] = 'code';
        $oauth_url = 'oauth/request?'.http_build_query($get_parameters);


        $params = [];
        $params['username']      = $username;
        $params['password']      = $password;
        $params['grant_access']   = 1;

        $result = $this->fetchFromAPI('POST', $oauth_url, $params);
        if (isset($result['error']) AND trim($result['error']) != ''){
            throw new \Exception($result['error']);
        }

        if (!isset($result['code'])){
            throw new \Exception('Unknown error retrieving authorization code');
        }

        return $result['code'];
    }

    public function getOAuthAccessToken($code)
    {
        $form_data = [
            'grant_type'    => 'authorization_code',
            'code'          => $code,
            'client_id'     => $this->client_id,
            'client_secret' => $this->client_secret,
            'redirect_uri'  => $this->redirect_uri,
        ];

        $result = $this->fetchFromOAuth('POST', 'oauth/access-token', $form_data);
        if (isset($result['error']) AND trim($result['error']) != ''){
            throw new \Exception($result['error']);
        }

        if (!isset($result['access_token'])){
            throw new \Exception('Unknown error retrieving access token');
        }

        return $result['access_token'];
    }

    public function getOAuthUserFromAccessToken($access_token)
    {
        $params = ['client_id' => $this->client_id, 'access_token' => $access_token];
        $result = $this->fetchFromOAuth('GET', 'oauth/user', $form_data);
        if (isset($result['error']) AND trim($result['error']) != ''){
            throw new \Exception($result['error']);
        }

        if (!isset($result['id'])){
            throw new \Exception('Unknown error retrieving user');
        }

        return $result['id'];
    }
    // ------------------------------------------------------------------------
	
    protected function fetchFromAPI($method, $path, $parameters=[]) {
        $url = $this->api_url.'/api/v1/'.ltrim($path, '/');
        return $this->fetchFromAccounts($method, $url, $parameters);
    }

    protected function fetchFromOAuth($method, $path, $parameters=[]) {
        $url = $this->api_url.'/'.ltrim($path, '/');
        return $this->fetchFromAccounts($method, $url, $parameters, 'form');
    }

    protected function fetchFromAccounts($method, $url, $parameters=[], $post_type='json') {
        $headers = [];
        $options = [];

        // build body
        if ($method == 'GET') {
            $body = $parameters;
        } else {
            if ($post_type == 'json') {
                $headers['Content-Type'] = 'application/json';
                $headers['Accept'] = 'application/json';
                if ($parameters) {
                    $body = json_encode($parameters);
                } else {
                    $body = null;
                }
            } else {
                // form fields (x-www-form-urlencoded)
                $body = $parameters;
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
