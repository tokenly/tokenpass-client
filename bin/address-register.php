#!/usr/bin/env php
<?php

use Tokenly\TokenpassClient\TokenpassAPI;

/*

# Usage:

export TOKENPASS_PROVIDER_HOST=https://tokenpass-stage.tokenly.com
export TOKENPASS_CLIENT_ID=xxxxx
export TOKENPASS_CLIENT_SECRET=xxxxx

./address-register.php <oauth_token> <address> <label>

*/ 

require __DIR__.'/init/bootstrap.php';

$api = new TokenpassAPI();

$oauth_token = $argv[1];
$address     = $argv[2];
$label       = $argv[3];
if (!$oauth_token) { throw new Exception("oauth_token is required", 1); }
if (!$address)     { throw new Exception("address is required", 1); }
if (!$label)       { throw new Exception("label is required", 1); }

// check
echo "registering address for token ".substr($oauth_token, 0, 4)."...\n";
$result = $api->registerAddress($address, $oauth_token, $label, $public = true, $active = true);


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
