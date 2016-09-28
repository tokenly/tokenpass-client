#!/usr/bin/env php
<?php

use Tokenly\TokenpassClient\TokenpassAPI;

/*

# Usage:

export TOKENPASS_PROVIDER_HOST=https://tokenpass-stage.tokenly.com
export TOKENPASS_CLIENT_ID=xxxxx
export TOKENPASS_CLIENT_SECRET=xxxxx

./provisional-register-source-address.php <address> <proof>

*/ 

require __DIR__.'/init/bootstrap.php';

$api = new TokenpassAPI();

// get vars
$address = $argv[1];
if (!$address) { throw new Exception("Address is required", 1); }
$proof = $argv[2];

if (!$proof) {
    $message = $address.'_'.hash('sha256', env('TOKENPASS_CLIENT_ID'));
    echo "Please sign this message with the private key of address $address:\n$message\n";
    exit(0);
}

// check
echo "registering $address with proof $proof\n";
$result = $api->registerProvisionalSource($address, $proof);

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
