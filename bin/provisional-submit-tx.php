#!/usr/bin/env php
<?php

use Tokenly\TokenpassClient\TokenpassAPI;

/*

# Usage:

export TOKENPASS_PROVIDER_HOST=https://tokenpass-stage.tokenly.com
export TOKENPASS_CLIENT_ID=xxxxx
export TOKENPASS_CLIENT_SECRET=xxxxx

./provisional-submit-tx.php <source> <destination> <token> <amount>

*/ 

require __DIR__.'/init/bootstrap.php';

$api = new TokenpassAPI();

// get vars
$source      = $argv[1];
$destination = $argv[2];
$token       = $argv[3];
$amount      = $argv[4];
if (!$source)      { throw new Exception("source is required", 1); }
if (!$destination) { throw new Exception("destination is required", 1); }
if (!$token)       { throw new Exception("token is required", 1); }
if (!$amount)      { throw new Exception("amount is required", 1); }

// check
echo "promising $source, $destination, $token, $amount\n";
$result = $api->promiseTransaction($source, $destination, $token, $amount, time()+3600);


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
