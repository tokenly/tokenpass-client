#!/usr/bin/env php
<?php

use Tokenly\TokenpassClient\TokenpassAPI;

/*

# Usage:

export TOKENPASS_PROVIDER_HOST=https://tokenpass-stage.tokenly.com
export TOKENPASS_CLIENT_ID=xxxxx
export TOKENPASS_CLIENT_SECRET=xxxxx

./address-verify.php <oauth_token> <address> <signature>

*/ 

require __DIR__.'/init/bootstrap.php';

$api = new TokenpassAPI();

// get vars
$oauth_token = $argv[1];
$address = $argv[2];
$signature = $argv[3];
if (!$oauth_token) { throw new Exception("oauth_token is required", 1); }
if (!$address) { throw new Exception("Address is required", 1); }
if (!$signature) { throw new Exception("signature is required", 1); }

// check
echo "verifying address $address with signature $signature\n";
$result = $api->verifyAddress($address, $oauth_token, $signature);

// handle error
if ($result === false) {
    $error_string = $api->getErrorsAsString();
    if ($error_string) {
        echo "ERROR: $error_string\n";
        exit(1);
    }
}

// show the results
echo "\$result: ".json_encode($result, 192)."\n";
