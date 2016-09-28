#!/usr/bin/env php
<?php

use Tokenly\TokenpassClient\TokenpassAPI;

/*

# Usage:

export TOKENPASS_PROVIDER_HOST=https://tokenpass-stage.tokenly.com
export TOKENPASS_CLIENT_ID=xxxxx
export TOKENPASS_CLIENT_SECRET=xxxxx

./addresses-list.php <oauth_token>

*/ 

require __DIR__.'/init/bootstrap.php';

$api = new TokenpassAPI();

$oauth_token = $argv[1];
if (!$oauth_token) { throw new Exception("oauth_token is required", 1); }

// check
echo "get addresses list for token ".substr($oauth_token, 0, 4)."...\n";
$result = $api->getAddressesForAuthenticatedUser($oauth_token);


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
