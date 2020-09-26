<?php
namespace Tokenly\TokenpassClient;

use Exception;
use Requests;
use GuzzleHttp\Client as HttpClient;
use Tokenly\TokenpassClient\Exception\TokenpassAPIException;

class TokenpassAPI
{
    public $redirect_uri  = false;
    public static $errors = array();
    protected $privileged_client_id = null;
    protected $privileged_client_secret = null;
    protected $oauth_client_id = null;
    protected $oauth_client_secret = null;

    function __construct($client_id, $client_secret, $privileged_client_id, $privileged_client_secret, $tokenpass_url, $redirect_uri, $oauth_client_id=null, $oauth_client_secret=null) {
        $this->client_id = $client_id;
        $this->client_secret = $client_secret;
        $this->privileged_client_id = $privileged_client_id;
        $this->privileged_client_secret = $privileged_client_secret;
        $this->tokenpass_url = $tokenpass_url;
        $this->redirect_uri = $redirect_uri;
        $this->oauth_client_id = $oauth_client_id;
        $this->oauth_client_secret = $oauth_client_secret;
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
            $call = $this->fetchFromTokenpassAPI('GET', 'tca/check/'.$username, $params, $oauth_token);
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
    /**
     * Checks token access by email address only
     * This inludes any promises sent to an email address that is not registered yet
     * This is a privileged API method and not available to OAUth clients
     * @param  string $email
     * @param  array  $rules
     * @return bool
     */
    public function checkTokenAccessByEmail($email, $rules)
    {
        try{
            $params = $this->normalizeGetParameters($rules);
            $call = $this->fetchFromTokenpassAPIWithPrivilegedAuth('GET', 'tca/checkemail/'.$email, $params);
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
            if ($refresh) { $params['refresh'] = '1'; }
            $call = $this->fetchFromTokenpassAPI('GET', 'tca/addresses', $params, $oauth_token);
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

    public function getOAuthAccessTokenWithCredentials($username, $password, $scopes)
    {
        $form_data = [
            'grant_type' => 'password',
            'client_id'     => $this->oauth_client_id,
            'client_secret' => $this->oauth_client_secret,
            'username'  => $username,
            'password'  => $password,
            'scopes'  => $scopes,
        ];

        try {
            $result = $this->fetchFromOAuth('POST', '/oauth/token', $form_data);
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
            $call = $this->fetchFromTokenpassAPI('GET', 'tca/address/'.$address, $params, $oauth_token);
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

    public function registerAddress($address, $oauth_token, $label = '', $public = false, $active = true, $type = 'bitcoin')
    {
        try{
            $params = [];
            $params['address'] = $address;
            $params['label'] = $label;
            $params['public'] = $public;
            $params['active'] = $active;
            $params['type'] = $type;
            $call = $this->fetchFromTokenpassAPI('POST', 'tca/address', $params, $oauth_token);
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
            $params['signature'] = $signature;
            $call = $this->fetchFromTokenpassAPI('POST', 'tca/address/'.$address, $params, $oauth_token);
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
            if($label !== null){
                $params['label'] = $label;
            }
            if($public !== null){
                $params['public'] = $public;
            }
            if($active !== null){
                $params['active'] = $active;
            }
            $call = $this->fetchFromTokenpassAPI('PATCH', 'tca/address/'.$address, $params, $oauth_token);
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
            $call = $this->fetchFromTokenpassAPI('DELETE', 'tca/address/'.$address, $params, $oauth_token);
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

    public function registerProvisionalSource($address, $chain = 'bitcoin', $proof = null, $assets = null, $extra_opts = array())
    {
		if($chain == 'counterparty'){
			$chain = 'bitcoin';
		}
		if($chain == 'counterpartyTestnet'){
			$chain = 'counterparty';
		}
        try{
            $params = [];
            $params['address'] = $address;
            $params['type'] = $chain;
            $params['proof'] = $proof;
            $params['assets'] = $assets;
            $valid_extra = array('assign_user', 'assign_user_hash', 'assign_user_label');
            foreach($valid_extra as $f){
                if(isset($extra_opts[$f])){
                    $params[$f] = $extra_opts[$f];
                }
            }
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
    public function registerProvisionalSourceWithProof($address, $assets = null, $extra_opts = array())
    {
		throw new Exception('Address signing with substation not yet implemented');

		/*
        $proof_message = $this->getProvisionalSourceProofMessage($address);
        $xchain = app('Tokenly\XChainClient\Client');
        $proof = false;
        $proof = $xchain->signMessage($address, $proof_message);
        if(!$proof OR !isset($proof['result'])){
            throw new Exception('Failed signing message');
        }
        $proof = $proof['result'];
        return $this->registerProvisionalSource($address, $proof, $assets, $extra_opts);
        * */
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
            $call = $this->fetchFromTokenpassAPI('DELETE', 'tca/provisional/'.$address);
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
    public function promiseTransaction($source, $destination, $asset, $quantity, $expiration, $txid = null, $fingerprint = null, $ref = null, $chain = 'bitcoin', $protocol = 'counterparty')
    {
        try{
            $params = [];
            $params['source'] = $source;
            $params['destination'] = $destination;
            $params['asset'] = $asset;
            $params['quantity'] = $quantity;
            $params['expiration'] = $expiration;
            $params['chain'] = $chain;
            $params['protocol'] = $protocol;
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
    public function getPromisedTransactionList($destination = null)
    {
        try{
            $params = [];
            if ($destination !== null) {
                $params['destination'] = $destination;
            }
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
    public function getPromisedTransactionListByEmailAddress($email)
    {
        try{
            $params = [];
            $call = $this->fetchFromTokenpassAPI('GET', 'tca/provisional/byemail/'.$email, $params);
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
            if(isset($data['note'])){
                $params['note'] = $data['note'];
            }
            if(isset($data['destination'])){
                $params['destination'] = $data['destination'];
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
            $params = [];
            if ($refresh) { $params['refresh'] = '1'; }
            $response = $this->fetchFromTokenpassAPI('GET', 'tca/public/balances', $params, $oauth_token);
        } catch (TokenpassAPIException $e) {
            self::$errors[] = $e->getMessage();
            return false;
        }
        return $response;
    }
    public function getCombinedProtectedBalances($oauth_token, $refresh = false)
    {
        try {
            $params = [];
            if ($refresh) { $params['refresh'] = '1'; }
            $response = $this->fetchFromTokenpassAPI('GET', 'tca/protected/balances', $params, $oauth_token);
        } catch (TokenpassAPIException $e) {
            self::$errors[] = $e->getMessage();
            return false;
        }
        return $response;
    }
    public function getChats($oauth_token)
    {
        try {
            $params = [];
            $response = $this->fetchFromTokenpassAPI('GET', 'tca/messenger/chats', $params, $oauth_token);
        } catch (TokenpassAPIException $e) {
            self::$errors[] = $e->getMessage();
            return false;
        }
        return $response;
    }

    public function joinChat($oauth_token, $chat_id)
    {
        try {
            $params = [];
            $response = $this->fetchFromTokenpassAPI('POST', 'tca/messenger/roster/'.$chat_id, $params, $oauth_token);
        } catch (TokenpassAPIException $e) {
            self::$errors[] = $e->getMessage();
            return false;
        }
        return true;
    }
    // ------------------------------------------------------------------------
    // managed chats
    public function getChat($oauth_token, $chat_uuid)
    {
        try {
            $params = [];
            $response = $this->fetchFromTokenpassAPI('GET', '/chat/'.$chat_uuid, $params, $oauth_token);
        } catch (TokenpassAPIException $e) {
            self::$errors[] = $e->getMessage();
            return false;
        }
        return $response;
    }
    /**
     * create a new chat
     * @param  string $oauth_token [description]
     * @param  array $create_vars  name, active, global, tca_rules ([['token' => 'MYTOKEN', 'quantity' => 100000000]])
     * @return array               new chat data
     */
    public function createChat($oauth_token, $create_vars)
    {
        try {
            $params = [];
            $response = $this->fetchFromTokenpassAPI('POST', '/chats', $params, $oauth_token);
        } catch (TokenpassAPIException $e) {
            self::$errors[] = $e->getMessage();
            return false;
        }
        return $response;
    }
    /**
     * updates an existing chat
     * @param  string $oauth_token [description]
     * @param  string $chat_uuid
     * @param  array $update_vars  active, global, tca_rules ([['token' => 'MYTOKEN', 'quantity' => 100000000]])
     * @return array               updated chat data
     */
    public function editChat($oauth_token, $chat_uuid, $update_vars)
    {
        try {
            $params = array_merge($update_vars, []);
            $response = $this->fetchFromTokenpassAPI('POST', '/chat/'.$chat_uuid, $params, $oauth_token);
        } catch (TokenpassAPIException $e) {
            self::$errors[] = $e->getMessage();
            return false;
        }
        return $response;
    }
    public function getChatPrivileges($oauth_token, $chat_id)
    {
        try {
            $params = [];
            $response = $this->fetchFromTokenpassAPI('GET', 'tca/messenger/chat/'.$chat_id, $params, $oauth_token);
        } catch (TokenpassAPIException $e) {
            self::$errors[] = $e->getMessage();
            return false;
        }
        return $response;
    }
    public function checkUserExists($username, $assign_user_hash=null, $strict=false)
    {
        try {
            $params = [];
            if ($assign_user_hash !== null) {
                $params['assign_user_hash'] = $assign_user_hash;
            }
            if ($strict) {
                $params['strict'] = '1';
            }
            $response = $this->fetchFromTokenpassAPIWithPrivilegedAuth('GET', 'lookup/user/exists/'.$username, $params);
        } catch (Exception $e) {
            throw $e;
        } catch (TokenpassAPIException $e) {
            self::$errors[] = $e->getMessage();
            return false;
        }
        if(!$response OR !$response['result']){
            return false;
        }
        return true;
    }

    /** App Credits API methods **/
    /******************************/

    public function newAppCreditGroup($name, $app_whitelist = array())
    {
        try {
            $params = array();
            $params['name'] = $name;
            if(is_string($app_whitelist)){
                $params['app_whitelist'] = $app_whitelist;
            }
            elseif(is_array($app_whitelist)){
                $params['app_whitelist'] = join("\n", $app_whitelist);
            }
            $response = $this->fetchFromTokenpassAPI('POST', 'credits', $params);
        } catch (TokenpassAPIException $e) {
            self::$errors[] = $e->getMessage();
            return false;
        }
        if(!$response){
            return false;
        }
        return $response['credit_group'];
    }

    public function updateAppCreditGroup($id, $data)
    {
        try {
            $params = array();
            if(isset($data['name'])){
                $params['name'] = $name;
            }
            if(isset($data['app_whitelist'])){
                if(is_string($data['app_whitelist'])){
                    $params['app_whitelist'] = $data['app_whitelist'];
                }
                elseif(is_array($data['app_whitelist'])){
                    $params['app_whitelist'] = join("\n", $data['app_whitelist']);
                }
            }
            $response = $this->fetchFromTokenpassAPI('PATCH', 'credits/'.$id, $params);
        } catch (TokenpassAPIException $e) {
            self::$errors[] = $e->getMessage();
            return false;
        }
        if(!$response){
            return false;
        }
        return $response['credit_group'];
    }

    public function listAppCreditGroups()
    {
        try{
            $call = $this->fetchFromTokenpassAPI('GET', 'credits');
        }
        catch(TokenpassAPIException $e){
            self::$errors[] = $e->getMessage();
            return false;
        }
        if(!isset($call['list'])){
            return false;
        }
        return $call['list'];
    }

    public function getAppCreditGroup($groupId)
    {
        try{
            $call = $this->fetchFromTokenpassAPI('GET', 'credits/'.$groupId);
        }
        catch(TokenpassAPIException $e){
            self::$errors[] = $e->getMessage();
            return false;
        }
        if(!isset($call['credit_group'])){
            return false;
        }
        return $call['credit_group'];
    }

    public function newAppCreditAccount($groupId, $name)
    {
        try {
            $params = array();
            $params['name'] = $name;
            $response = $this->fetchFromTokenpassAPI('POST', 'credits/'.$groupId.'/accounts', $params);
        } catch (TokenpassAPIException $e) {
            self::$errors[] = $e->getMessage();
            return false;
        }
        if(!$response){
            return false;
        }
        return $response['account'];
    }

    public function listAppCreditAccounts($groupId)
    {
        try{
            $call = $this->fetchFromTokenpassAPI('GET', 'credits/'.$groupId.'/accounts');
        }
        catch(TokenpassAPIException $e){
            self::$errors[] = $e->getMessage();
            return false;
        }
        if(!isset($call['accounts'])){
            return false;
        }
        return $call['accounts'];
    }

    public function getAppCreditAccount($groupId, $accountId)
    {
        try{
            $call = $this->fetchFromTokenpassAPI('GET', 'credits/'.$groupId.'/accounts/'.$accountId);
        }
        catch(TokenpassAPIException $e){
            self::$errors[] = $e->getMessage();
            return false;
        }
        if(!isset($call['account'])){
            return false;
        }
        return $call['account'];
    }

    public function getAppCreditAccountBalance($groupId, $accountId)
    {
        $get = $this->getAppCreditAccount($groupId, $accountId);
        if(!$get){
            return false;
        }
        return $get['balance'];
    }

    public function giveAppCredit($groupId, $account, $amount, $ref = null, $source = null)
    {
        $accounts_amounts = array();
        $item = array('account' => $account, 'amount' => $amount, 'ref' => $ref);
        if($source !== null){
            $item['source'] = $source;
        }
        $accounts_amounts[] = $item;
        return $this->giveMultipleAppCredit($groupId, $accounts_amounts);
    }

    public function takeAppCredit($groupId, $account, $amount, $ref = null, $destination = null)
    {
        $accounts_amounts = array();
        $item = array('account' => $account, 'amount' => $amount, 'ref' => $ref);
        if($destination !== null){
            $item['destination'] = $destination;
        }
        $accounts_amounts[] = $item;
        return $this->takeMultipleAppCredit($groupId, $accounts_amounts);
    }

    public function giveMultipleAppCredit($groupId, $accounts_amounts)
    {
        //$accounts_amounts = array(array('account' => <account_uuid>, 'amount' => 5000, 'source' => <source_account_uuid>|null))
        try{
            $params = array();
            $params['accounts'] = $accounts_amounts;
            $call = $this->fetchFromTokenpassAPI('POST', 'credits/'.$groupId.'/accounts/credit', $params);
        }
        catch(TokenpassAPIException $e){
            self::$errors[] = $e->getMessage();
            return false;
        }
        if(!isset($call['transactions'])){
            return false;
        }
        return $call['transactions'];
    }

    public function takeMultipleAppCredit($groupId, $accounts_amounts)
    {
        //$accounts_amounts = array(array('account' => <account_uuid>, 'amount' => 5000, 'destination' => <destination_account_uuid>|null))
        try{
            $params = array();
            $params['accounts'] = $accounts_amounts;
            $call = $this->fetchFromTokenpassAPI('POST', 'credits/'.$groupId.'/accounts/debit', $params);
        }
        catch(TokenpassAPIException $e){
            self::$errors[] = $e->getMessage();
            return false;
        }
        if(!isset($call['transactions'])){
            return false;
        }
        return $call['transactions'];
    }

    public function creditMultipleAppCredit($groupId, $accounts_amounts)
    {
        //alias
        return $this->giveMultipleAppCredit($groupId, $accounts_amounts);
    }

    public function debitMultipleAppCredit($groupId, $accounts_amounts)
    {
        //alias
        return $this->takeMultipleAppCredit($groupId, $accounts_amounts);
    }

    public function getAppCreditGroupHistory($groupId)
    {
        try{
            $call = $this->fetchFromTokenpassAPI('GET', 'credits/'.$groupId.'/history');
        }
        catch(TokenpassAPIException $e){
            self::$errors[] = $e->getMessage();
            return false;
        }
        return $call;
    }

    public function getAppCreditAccountHistory($groupId, $account)
    {
        try{
            $call = $this->fetchFromTokenpassAPI('GET', 'credits/'.$groupId.'/accounts/'.$account.'/history');
        }
        catch(TokenpassAPIException $e){
            self::$errors[] = $e->getMessage();
            return false;
        }
        return $call;
    }

    /** END App Credit API Methods **/
    public function getTokenPerks($token) {
        try {
            $result = $this->fetchFromPublicTokenpassAPI('GET', 'perks/'.$token);
        }
        catch (TokenpassAPIException $e) {
            self::$errors[] = $e->getMessage();
            return false;
        }
        return $result;
    }
    public function lookupUserByEmail($email)
    {
        try{
            $params = ['client_id' => $this->client_id];
            $call = $this->fetchFromTokenpassAPI('GET', 'lookup/email/'.$email, $params);
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

    // ------------------------------------------------------------------------

    protected function normalizeGetParameters($raw_params) {
        $out = [];
        foreach($raw_params as $k => $v) {
            $out[$k] = (string)$v;
        }
        return $out;
    }
    // ------------------------------------------------------------------------
    protected function fetchFromPublicTokenpassAPI($method, $path, $parameters=[]) {
        return $this->fetchFromTokenpassAPI($method, $path, $parameters, null, ['public' => true]);
    }
    protected function fetchFromTokenpassAPI($method, $path, $parameters=[], $oauth_token=null, $options=[]) {
        /*
        // use a Bearer token
        if ($oauth_token !== null AND strlen($oauth_token)) {
            $options['headers'] = isset($options['headers']) ? $options['headers'] : [];
            $options['headers']['Authorization'] = "Bearer ".$oauth_token;
        }
        */
        $parameters['oauth_token'] = $oauth_token;
        $url = '/api/v1/'.ltrim($path, '/');
        return $this->fetchFromTokenpass($method, $url, $parameters, 'json', $options);
    }
    protected function fetchFromOAuth($method, $path, $parameters=[]) {
        $url = '/'.ltrim($path, '/');
        return $this->fetchFromTokenpass($method, $url, $parameters, 'form');
    }
    protected function fetchFromTokenpass($method, $url, $parameters=[], $post_type='json', $options=[]) {
        $options['post_type'] = $post_type;
        try {
            return $this->call($method, $url, $parameters, $options);
        } catch (Exception $e) {
            throw new TokenpassAPIException($e->getMessage(), $e->getCode(), $e);
        }
    }
    protected function fetchFromTokenpassAPIWithPrivilegedAuth($method, $path, $parameters=[]) {
        try {
            // save the client id and secret
            $old_client_id       = $this->client_id;
            $old_client_secret   = $this->client_secret;
            // use the privileged client id and secret
            $this->client_id     = $this->privileged_client_id;
            $this->client_secret = $this->privileged_client_secret;
            $result = $this->fetchFromTokenpassAPI($method, $path, $parameters);
        } finally {
            // restore the client id and secret
            //   even if an exception was thrown
            $this->client_id     = $old_client_id;
            $this->client_secret = $old_client_secret;
        }
        return $result;
    }


    public function call($method, $endpoint, $params = [], $options = [])
    {
      //start client
      $client = new HttpClient();

      $data = $options;
      $data['json'] = $params;

      //generate a random nonce
      $nonce = hash_hmac('sha256', random_bytes(256).time(), $this->client_secret);

      $data['headers'] = [
        'X-API-Key' => $this->client_id,
        'X-API-Nonce' => $nonce,
        'X-API-Signature' => hash_hmac('sha256', $nonce.json_encode($params), $this->client_secret)
      ];

      //send the request
      try{
        $response = $client->request($method, $this->tokenpass_url.'/'.ltrim($endpoint, '/'), $data);
        if($response->getStatusCode() != 200){
          throw new Exception('Invalid API endpoint status code');
        }

        //decode response
        $json = json_decode($response->getBody(), true);
        if(!is_array($json)){
          throw new Exception('Invalid JSON response');
        }
      }
      catch(Exception $e){
        throw new Exception('Invalid response: '.$e->getMessage());
      }

      //return output
      return $json;
    }

}
