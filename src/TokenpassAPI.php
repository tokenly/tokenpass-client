<?php

namespace Tokenly\TokenpassClient;

use Exception;
use Requests;
use Tokenly\APIClient\TokenlyAPI;
use Tokenly\HmacAuth\Generator;
use Tokenly\TokenpassClient\Exception\TokenpassAPIException;

class TokenpassAPI extends TokenlyAPI
{
    public $redirect_uri  = false;
    public static $errors = array();

	function __construct() {
		if(function_exists('env')){
            $client_id           = env('TOKENPASS_CLIENT_ID');
            $client_secret       = env('TOKENPASS_CLIENT_SECRET');
            $api_url             = env('TOKENPASS_PROVIDER_HOST');

            $this->redirect_uri  = env('TOKENPASS_REDIRECT_URI');
		}
		else{
            $client_id           = (defined('TOKENPASS_CLIENT_ID')     ? constant('TOKENPASS_CLIENT_ID')     : null);
            $api_url             = (defined('TOKENPASS_PROVIDER_HOST') ? constant('TOKENPASS_PROVIDER_HOST') : null);
            $client_secret       = (defined('TOKENPASS_CLIENT_SECRET') ? constant('TOKENPASS_CLIENT_SECRET') : null);

            $this->redirect_uri  = (defined('TOKENPASS_REDIRECT_URI')  ? constant('TOKENPASS_REDIRECT_URI')  : null);
		}

        $authentication_generator = new Generator();
        parent::__construct($api_url, $authentication_generator, $client_id, $client_secret);
	}

    public function clearErrors() {
        return self::$errors = [];
    }

    public function getErrors() {
        return self::$errors;
    }

    public function getErrorsAsString() {
        return implode(', ', self::$errors);
    }
	
    // ------------------------------------------------------------------------
    
	public function checkTokenAccess($username, $rules, $oauth_token)
	{
		try{
            $params = $this->normalizeGetParameters($rules);
            $params['oauth_token'] = $oauth_token;
			$call = $this->fetchFromTokenpassAPI('GET', 'tca/check/'.$username, $params);
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
	
	public function getPublicAddresses($username, $refresh=false)
	{
		try{
            $get_parameters = [];
            if ($refresh) { $get_parameters['refresh'] = '1'; }
			$call = $this->fetchFromTokenpassAPI('GET', 'tca/addresses/'.$username, $get_parameters);
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
	
	public function getAddressesForAuthenticatedUser($oauth_token, $refresh = false)
	{
		try{
            $params = [];
			if($oauth_token){
				$params['oauth_token'] = $oauth_token;
            }
			if ($refresh) { $params['refresh'] = '1'; }
			$call = $this->fetchFromTokenpassAPI('GET', 'tca/addresses', $params);
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

    // deprecated - use getAddressesForAuthenticatedUser or getPublicAddresses
    public function getAddresses($username = false, $oauth_token = false, $refresh = false) {
        if ($oauth_token) {
            return $this->getAddressesForAuthenticatedUser($oauth_token, $refresh);
        }

        if ($username) {
            return $this->getPublicAddresses($username, $refresh);
        }
    }

	
	public function checkAddressTokenAccess($address, $rules = array())
	{
		$body = $rules;
		try{
			$call = $this->fetchFromTokenpassAPI('GET', 'tca/check-address/'.$address, $body);
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
			$call = $this->fetchFromTokenpassAPI('PATCH', 'update', $params);
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
			$result = $this->fetchFromTokenpassAPI('POST', 'register', $params);
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
			$result = $this->fetchFromTokenpassAPI('POST', 'login', $params);
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
			$result = $this->fetchFromTokenpassAPI('POST', $oauth_url, $params);
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
    
    
    public function getPublicAddressDetails($username, $address)
    {
        try{
            $params = [];
            $call = $this->fetchFromTokenpassAPI('GET', 'tca/addresses/'.$username.'/'.$address, $params);
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
    
    public function getAddressDetailsForAuthenticatedUser($address, $oauth_token)
    {
		try{
            $params = [];
			$params['oauth_token'] = $oauth_token;
			$call = $this->fetchFromTokenpassAPI('GET', 'tca/address/'.$address, $params);
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

    // deprecated - use getPublicAddressDetails or getAddressDetailsForAuthenticatedUser
    public function getAddressDetails($username, $address, $oauth_token = false) {
        if ($oauth_token) {
            return $this->getAddressDetailsForAuthenticatedUser($address, $oauth_token);
        }
        return $this->getPublicAddressDetails($username, $address);
    }
	
	public function registerAddress($address, $oauth_token, $label = '', $public = false, $active = true)
	{
		try{
            $params = [];
			$params['oauth_token'] = $oauth_token;
			$params['address'] = $address;
			$params['label'] = $label;
			$params['public'] = $public;
			$params['active'] = $active;
			$call = $this->fetchFromTokenpassAPI('POST', 'tca/address', $params);
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
	
	public function verifyAddress($address, $oauth_token, $signature)
	{
        // handle legacy clients
        if (func_num_args() == 4) {
            $old_args = func_get_args();
            list($username, $address, $oauth_token, $signature) = $old_args;
        }

		try{
            $params = [];
			$params['oauth_token'] = $oauth_token;
			$params['signature'] = $signature;
			$call = $this->fetchFromTokenpassAPI('POST', 'tca/address/'.$address, $params);
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
	
	public function updateAddressDetails($address, $oauth_token, $label = null, $public = null, $active = null)
	{
        // handle legacy clients
        $old_args = func_get_args();
        if (substr($old_args[1], 0, 1) == '1' OR substr($old_args[1], 0, 1) == '3') {
            list($username, $address, $oauth_token, $label, $public, $active) = $old_args;
        }


		try{
			$params = [];
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
			$call = $this->fetchFromTokenpassAPI('PATCH', 'tca/address/'.$address, $params);
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
	
	public function deleteAddress($address, $oauth_token)
	{
        // handle legacy clients
        if (func_num_args() == 3) {
            $old_args = func_get_args();
            list($username, $address, $oauth_token) = $old_args;
        }

		try{
            $params = [];
			$params['oauth_token'] = $oauth_token;
			$call = $this->fetchFromTokenpassAPI('DELETE', 'tca/address/'.$address, $params);
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
        $params = [];
        $method = 'GET';
        if(is_array($address)){
            $params['address_list'] = $address;
            $method = 'POST';
            $address = 'null';
        }
        try{
            $call = $this->fetchFromTokenpassAPI($method, 'lookup/address/'.$address, $params);
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
            $params = [];
			$call = $this->fetchFromTokenpassAPI('GET', 'lookup/user/'.$username, $params);
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
            $params = [];
            $params['address'] = $address;
            $params['proof'] = $proof;
            $params['assets'] = $assets;
            $call = $this->fetchFromTokenpassAPI('POST', 'tca/provisional/register', $params);
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
        if(!$proof OR !isset($proof['result'])){
            throw new Exception('Failed signing message');
        }
        $proof = $proof['result'];
        return $this->registerProvisionalSource($address, $proof, $assets);
    }

    public function getProvisionalSourceList()
    {
        try{
            $params = [];
            $call = $this->fetchFromTokenpassAPI('GET', 'tca/provisional', $params);
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
            $params = [];
            $call = $this->fetchFromTokenpassAPI('GET', 'tca/provisional', $params);
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
            $call = $this->fetchFromTokenpassAPI('DELETE', 'tca/provisional/'.$address, $params);
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
            $params = [];
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
            $call = $this->fetchFromTokenpassAPI('POST', 'tca/provisional/tx', $params);
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
            $params = [];
            $call = $this->fetchFromTokenpassAPI('GET', 'tca/provisional/tx/'.$id, $params);
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
            $params = [];
            $call = $this->fetchFromTokenpassAPI('GET', 'tca/provisional/tx', $params);
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
            $params = [];
            $call = $this->fetchFromTokenpassAPI('DELETE', 'tca/provisional/tx/'.$id, $params);
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
            $params = [];
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
            $call = $this->fetchFromTokenpassAPI('PATCH', 'tca/provisional/tx/'.$id, $params);
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

    public function getCombinedPublicBalances($oauth_token, $refresh = false)
    {
        try {
            $params = ['oauth_token' => $oauth_token];
            if ($refresh) { $params['refresh'] = '1'; }
            $response = $this->fetchFromTokenpassAPI('GET', 'tca/public/balances', $params);
        } catch (TokenpassAPIException $e) {
            self::$errors[] = $e->getMessage();
            return false;
        }

        return $response;
    }

    public function getCombinedProtectedBalances($oauth_token, $refresh = false)
    {
        try {
            $params = ['oauth_token' => $oauth_token];
            if ($refresh) { $params['refresh'] = '1'; }
            $response = $this->fetchFromTokenpassAPI('GET', 'tca/protected/balances', $params);
        } catch (TokenpassAPIException $e) {
            self::$errors[] = $e->getMessage();
            return false;
        }

        return $response;
    }

    public function joinChat($oauth_token, $chat_id)
    {
        try {
            $params = ['oauth_token' => $oauth_token];
            $response = $this->fetchFromTokenpassAPI('POST', 'tca/messenger/roster/'.$chat_id, $params);
        } catch (TokenpassAPIException $e) {
            self::$errors[] = $e->getMessage();
            return false;
        }

        return true;
    }

	
    // ------------------------------------------------------------------------
    
    protected function normalizeGetParameters($raw_params) {
        $out = [];
        foreach($raw_params as $k => $v) {
            $out[$k] = (string)$v;
        }
        return $out;
    }

    // ------------------------------------------------------------------------
	
    protected function fetchFromTokenpassAPI($method, $path, $parameters=[]) {
        $url = '/api/v1/'.ltrim($path, '/');
        return $this->fetchFromTokenpass($method, $url, $parameters);
    }

    protected function fetchFromOAuth($method, $path, $parameters=[]) {
        $url = '/'.ltrim($path, '/');
        return $this->fetchFromTokenpass($method, $url, $parameters, 'form');
    }

    protected function fetchFromTokenpass($method, $url, $parameters=[], $post_type='json') {
        $options = [
            'post_type' => $post_type,
        ];
        try {
            return $this->call($method, $url, $parameters, $options);
        } catch (Exception $e) {
            throw new TokenpassAPIException($e->getMessage(), $e->getCode(), $e);
        }
    }

}
