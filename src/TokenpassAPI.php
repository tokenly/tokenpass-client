<?php

namespace Tokenly\TokenpassClient;

use Exception;
use Requests;
use Tokenly\TokenpassClient\Exception\TokenpassAPIException;

class TokenpassAPI
{
    public $client_id     = false;
    public $client_secret = false;
    public $api_url       = false;
    public $redirect_uri  = false;
    public static $errors = array();

	function __construct()
	{
		if(function_exists('env')){
            $this->client_id     = env('TOKENPASS_CLIENT_ID');
            $this->client_secret = env('TOKENPASS_CLIENT_SECRET');
            $this->api_url       = env('TOKENPASS_PROVIDER_HOST');
            $this->redirect_uri  = env('TOKENPASS_REDIRECT_URI');
		}
		else{
            $this->client_id     = (defined('TOKENPASS_CLIENT_ID')     ? constant('TOKENPASS_CLIENT_ID')     : null);
            $this->api_url       = (defined('TOKENPASS_PROVIDER_HOST') ? constant('TOKENPASS_PROVIDER_HOST') : null);
            $this->redirect_uri  = (defined('TOKENPASS_REDIRECT_URI')  ? constant('TOKENPASS_REDIRECT_URI')  : null);
            $this->client_secret = (defined('TOKENPASS_CLIENT_SECRET') ? constant('TOKENPASS_CLIENT_SECRET') : null);
		}
	}
	
	public function checkTokenAccess($username, $rules = array())
	{
		$rules['client_id'] = $this->client_id;
		try{
			$call = $this->fetchFromAPI('GET', 'tca/check/'.$username, $rules);
		}
		catch(TokenpassAPIException $e){
			self::$errors[] = $e->getMessage();
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
		catch(TokenpassAPIException $e){
			self::$errors[] = $e->getMessage();
			return false;
		}
		if(!isset($call['result'])){
			return false;
		}
		return $call['result'];
	}
	
	public function getAddresses($username, $oauth_token = false, $refresh = false)
	{
		try{
			$params = array('client_id' => $this->client_id);
			if($oauth_token){
				$params['oauth_token'] = $oauth_token;
				if($refresh){
					$username .= '/refresh';
				}
			}
			$call = $this->fetchFromAPI('GET', 'tca/addresses/'.$username, $params);
		}
		catch(TokenpassAPIException $e){
			self::$errors[] = $e->getMessage();
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
		catch(TokenpassAPIException $e){
			self::$errors[] = $e->getMessage();
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
		try{
			$call = $this->fetchFromAPI('PATCH', 'update', $params);
		}
		catch(TokenpassAPIException $e){
			throw new \Exception($e->getMessage());
		}
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

		try{
			$result = $this->fetchFromAPI('POST', 'register', $params);
		}
		catch(TokenpassAPIException $e){
			throw new \Exception($e->getMessage());
		}

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
		
		try{
			$result = $this->fetchFromAPI('POST', 'login', $params);
		}
		catch(TokenpassAPIException $e){
			throw new \Exception($e->getMessage());
		}

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
		try{
			$result = $this->fetchFromAPI('POST', $oauth_url, $params);
		}
		catch(TokenpassAPIException $e){
			throw new \Exception($e->getMessage());
		}
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
		
		try{
			$result = $this->fetchFromOAuth('POST', 'oauth/access-token', $form_data);
		}
		catch(TokenpassAPIException $e){
			throw new \Exception($e->getMessage());
		}
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
        try{
			$result = $this->fetchFromOAuth('GET', 'oauth/user', $form_data);
		}
		catch(TokenpassAPIException $e){
			throw new \Exception($e->getMessage());
		}
        if (isset($result['error']) AND trim($result['error']) != ''){
            throw new \Exception($result['error']);
        }

        if (!isset($result['id'])){
            throw new \Exception('Unknown error retrieving user');
        }

        return $result['id'];
    }
    
    
    public function getAddressDetails($username, $address, $oauth_token = false)
    {
		try{
			$params = array('client_id' => $this->client_id);
			if($oauth_token){
				$params['oauth_token'] = $oauth_token;
			}
			$call = $this->fetchFromAPI('GET', 'tca/addresses/'.$username.'/'.$address, $params);
		}
		catch(TokenpassAPIException $e){
			self::$errors[] = $e->getMessage();
			return false;
		}
		if(!isset($call['result'])){
			return false;
		}
		return $call['result'];
	}
	
	public function registerAddress($address, $oauth_token, $label = '', $public = false, $active = true)
	{
		try{
			$params = array('client_id' => $this->client_id);
			$params['oauth_token'] = $oauth_token;
			$params['address'] = $address;
			$params['label'] = $label;
			$params['public'] = $public;
			$params['active'] = $active;
			$call = $this->fetchFromAPI('POST', 'tca/addresses', $params);
		}
		catch(Exception $e){
			self::$errors[] = $e->getMessage();
			return false;
		}
		if(!isset($call['result'])){
			return false;
		}
		return $call['result'];
	}
	
	public function verifyAddress($username, $address, $oauth_token, $signature)
	{
		try{
			$params = array('client_id' => $this->client_id);
			$params['oauth_token'] = $oauth_token;
			$params['signature'] = $signature;
			$call = $this->fetchFromAPI('POST', 'tca/addresses/'.$username.'/'.$address, $params);
		}
		catch(Exception $e){
			self::$errors[] = $e->getMessage();
			return false;
		}
		if(!isset($call['result'])){
			return false;
		}
		return $call['result'];
	}
	
	public function updateAddressDetails($username, $address, $oauth_token, $label = null, $public = null, $active = null)
	{
		try{
			$params = array('client_id' => $this->client_id);
			$params['oauth_token'] = $oauth_token;
			if($label !== null){
				$params['label'] = $label;
			}
			if($public !== null){
				$params['public'] = $public;
			}
			if($active !== null){
				$params['active'] = $active;
			}
			$call = $this->fetchFromAPI('PATCH', 'tca/addresses/'.$username.'/'.$address, $params);
		}
		catch(Exception $e){
			self::$errors[] = $e->getMessage();
			return false;
		}
		if(!isset($call['result'])){
			return false;
		}
		return $call['result'];
	}
	
	public function deleteAddress($username, $address, $oauth_token)
	{
		try{
			$params = array('client_id' => $this->client_id);
			$params['oauth_token'] = $oauth_token;
			$call = $this->fetchFromAPI('DELETE', 'tca/addresses/'.$username.'/'.$address, $params);
		}
		catch(Exception $e){
			self::$errors[] = $e->getMessage();
			return false;
		}
		if(!isset($call['result'])){
			return false;
		}
		return $call['result'];	
	}
	
	public function lookupUserByAddress($address)
	{
        $params = array('client_id' => $this->client_id);
        $method = 'GET';
        if(is_array($address)){
            $params['address_list'] = $address;
            $method = 'POST';
            $address = 'null';
        }
        try{
            $call = $this->fetchFromAPI($method, 'lookup/address/'.$address, $params);
        }
        catch(TokenpassAPIException $e){
            self::$errors[] = $e->getMessage();
            return false;
        }
		if(!isset($call['result'])){
			return false;
		}
		return $call;
	}
	
	public function lookupAddressByUser($username)
	{
		try{
			$params = array('client_id' => $this->client_id);
			$call = $this->fetchFromAPI('GET', 'lookup/user/'.$username, $params);
		}
		catch(TokenpassAPIException $e){
			self::$errors[] = $e->getMessage();
			return false;
		}
		if(!isset($call['result'])){
			return false;
		}
		return $call;
	}
    
    public function registerProvisionalSource($address, $proof, $assets = null)
    {
        try{
            $params = array('client_id' => $this->client_id);
            $params['address'] = $address;
            $params['proof'] = $proof;
            $params['assets'] = $assets;
            $call = $this->fetchFromAPI('POST', 'tca/provisional', $params);
        }
        catch(TokenpassAPIException $e){
            self::$errors[] = $e->getMessage();
            throw new Exception($e->getMessage());
        }
        if(!isset($call['result'])){
            throw new Exception('Unkown error registering provisional source');
        }
        if(!$call['result']){
            if(isset($call['error'])){
                throw new Exception($call['error']);
            }
        }
        return $call['result'];
    }

    public function registerProvisionalSourceWithProof($address, $assets = null)
    {
        $proof_message = $this->getProvisionalSourceProofMessage($address);
        $xchain = app('Tokenly\XChainClient\Client');
        $proof = false;
        $proof = $xchain->signMessage($address, $proof_message);
        if(!$proof){
            throw new Exception('Failed signing message');
        }
        return $this->registerProvisionalSource($address, $proof, $assets);
    }

    public function getProvisionalSourceList()
    {
        try{
            $params = array('client_id' => $this->client_id);
            $call = $this->fetchFromAPI('GET', 'tca/provisional', $params);
        }
        catch(TokenpassAPIException $e){
            self::$errors[] = $e->getMessage();
            return false;
        }
        if(!isset($call['result'])){
            return false;
        }
        return $call['whitelist'];
    }

    public function getProvisionalSourceProofSuffix()
    {
        try{
            $params = array('client_id' => $this->client_id);
            $call = $this->fetchFromAPI('GET', 'tca/provisional', $params);
        }
        catch(TokenpassAPIException $e){
            self::$errors[] = $e->getMessage();
            return false;
        }
        if(!isset($call['result'])){
            return false;
        }
        return $call['proof_suffix'];
    }

    public function getProvisionalSourceProofMessage($address)
    {
        $suffix = $this->getProvisionalSourceProofSuffix();
        if(!$suffix){
            return false;
        }
        return $address.$suffix;
    }

    public function deleteProvisionalSource($address)
    {
        try{
            $params = array('client_id' => $this->client_id);
            $call = $this->fetchFromAPI('DELETE', 'tca/provisional/'.$address, $params);
        }
        catch(TokenpassAPIException $e){
            self::$errors[] = $e->getMessage();
            return false;
        }
        if(!isset($call['result'])){
            return false;
        }
        return $call['result'];
    }

    public function promiseTransaction($source, $destination, $asset, $quantity, $expiration, $txid = null, $fingerprint = null, $ref = null)
    {
        try{
            $params = array('client_id' => $this->client_id);
            $params['source'] = $source;
            $params['destination'] = $destination;
            $params['asset'] = $asset;
            $params['quantity'] = $quantity;
            $params['expiration'] = $expiration;
            if($txid != null){
                $params['txid'] = $txid;
            }
            if($fingerprint != null){
                $params['fingerprint'] = $fingerprint;
            }
            $params['ref'] = $ref;
            $call = $this->fetchFromAPI('POST', 'tca/provisional/tx', $params);
        }
        catch(TokenpassAPIException $e){
            self::$errors[] = $e->getMessage();
            return false;
        }
        if(!isset($call['result'])){
            return false;
        }
        return $call['tx'];
    }

    public function getPromisedTransaction($id)
    {
        try{
            $params = array('client_id' => $this->client_id);
            $call = $this->fetchFromAPI('GET', 'tca/provisional/tx/'.$id, $params);
        }
        catch(TokenpassAPIException $e){
            self::$errors[] = $e->getMessage();
            return false;
        }
        if(!isset($call['result'])){
            return false;
        }
        return $call['tx'];
    }

    public function getPromisedTransactionList()
    {
        try{
            $params = array('client_id' => $this->client_id);
            $call = $this->fetchFromAPI('GET', 'tca/provisional/tx', $params);
        }
        catch(TokenpassAPIException $e){
            self::$errors[] = $e->getMessage();
            return false;
        }
        if(!isset($call['result'])){
            return false;
        }
        return $call['list'];
    }

    public function deletePromisedTransaction($id)
    {
        try{
            $params = array('client_id' => $this->client_id);
            $call = $this->fetchFromAPI('DELETE', 'tca/provisional/tx/'.$id, $params);
        }
        catch(TokenpassAPIException $e){
            self::$errors[] = $e->getMessage();
            return false;
        }
        if(!isset($call['result'])){
            return false;
        }
        return $call['result'];
    }

    public function updatePromisedTransaction($id, $data)
    {
        try{
            $params = array('client_id' => $this->client_id);
            if(isset($data['quantity'])){
                $params['quantity'] = $data['quantity'];
            }
            if(isset($data['expiration'])){
                $params['expiration'] = $data['expiration'];
            }
            if(isset($data['txid'])){
                $params['txid'] = $data['txid'];
            }
            if(isset($data['fingerprint'])){
                $params['fingerprint'] = $data['fingerprint'];
            }
            if(isset($data['ref'])){
                $params['ref'] = $data['ref'];
            }
            $call = $this->fetchFromAPI('PATCH', 'tca/provisional/tx/'.$id, $params);
        }
        catch(TokenpassAPIException $e){
            self::$errors[] = $e->getMessage();
            return false;
        }
        if(!isset($call['result'])){
            return false;
        }
        return $call['tx'];
    }

	

    // ------------------------------------------------------------------------
	
    protected function fetchFromAPI($method, $path, $parameters=[]) {
        $url = $this->api_url.'/api/v1/'.ltrim($path, '/');
        return $this->fetchFromTokenpass($method, $url, $parameters);
    }

    protected function fetchFromOAuth($method, $path, $parameters=[]) {
        $url = $this->api_url.'/'.ltrim($path, '/');
        return $this->fetchFromTokenpass($method, $url, $parameters, 'form');
    }

    protected function fetchFromTokenpass($method, $url, $parameters=[], $post_type='json') {
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
					if($method == 'DELETE'){
						$body = $parameters;
					}
					else{
						$body = json_encode($parameters);
					}
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
            throw new TokenpassAPIException("Unexpected response", 1);
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
            throw new TokenpassAPIException($error_message, $error_code);
        }

        return $json;
    }

}
