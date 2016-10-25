#!/usr/bin/env php
<?php

use Tokenly\TokenpassClient\TokenpassAPI;

/*

# Usage:

export TOKENPASS_PROVIDER_HOST=https://tokenpass-stage.tokenly.com
export TOKENPASS_CLIENT_ID=xxxxx
export TOKENPASS_CLIENT_SECRET=xxxxx

./check-username-tca.php <oauth_token> <username> <rules>

*/ 

require __DIR__.'/init/bootstrap.php';

$api = new TokenpassAPI();

// get vars
$oauth_token = $argv[1];
$username = $argv[2];
$rules = json_decode($argv[3], true);

// check
echo "Checking user $username with rules: ".json_encode($rules)."\n";
$result = $api->checkTokenAccess($username, $rules, $oauth_token);

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
