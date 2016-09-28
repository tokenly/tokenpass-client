#!/usr/bin/env php
<?php

use Tokenly\TokenpassClient\TokenpassAPI;

/*

# Usage:

export TOKENPASS_PROVIDER_HOST=https://tokenpass-stage.tokenly.com
export TOKENPASS_CLIENT_ID=xxxxx
export TOKENPASS_CLIENT_SECRET=xxxxx

lookup-addresses-list.php <username> <refresh>

*/ 

require __DIR__.'/init/bootstrap.php';

$api = new TokenpassAPI();

$username = $argv[1];
if (!$username) { throw new Exception("username is required", 1); }
$refresh = !!(isset($argv[2]) ? $argv[2] : false);


// check
echo "get addresses list\n";
$result = $api->getPublicAddresses($username, $refresh);


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
