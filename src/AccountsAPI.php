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
	
	
    protected function fetchFromAPI($method, $path, $parameters=[]) {
        $api_path = $this->base_path.'/'.ltrim($path, '/');

        $client = new GuzzleClient(['base_url' => env('TOKENLY_ACCOUNTS_PROVIDER_HOST').'/api/v1']);

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
                    $auth_exception->setJSONResponse($json);
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
            $auth_exception->setJSONResponse($json);
            throw $auth_exception;
        }

        return $json;
    }
	
}
