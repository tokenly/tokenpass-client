#!/usr/bin/env php
<?php

use Tokenly\TokenpassClient\TokenpassAPI;

/*

# Usage:

export TOKENPASS_PROVIDER_HOST=https://tokenpass-stage.tokenly.com
export TOKENPASS_CLIENT_ID=xxxxx
export TOKENPASS_CLIENT_SECRET=xxxxx

./public-address-details <username> <address>

*/ 

require __DIR__.'/init/bootstrap.php';

$api = new TokenpassAPI();

$username = $argv[1];
$address  = $argv[2];
if (!$username) { throw new Exception("username is required", 1); }
if (!$address)  { throw new Exception("address is required", 1); }

// check
echo "fetching public address details for $username $address\n";
$result = $api->getPublicAddressDetails($username, $address);


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
