#!/usr/bin/env php
<?php

use Tokenly\TokenpassClient\TokenpassAPI;

/*

# Usage:

export TOKENPASS_PROVIDER_HOST=https://tokenpass-stage.tokenly.com
export TOKENPASS_CLIENT_ID=xxxxx
export TOKENPASS_CLIENT_SECRET=xxxxx

./provisional-update-tx.php <promise_id> <amount>

*/ 

require __DIR__.'/init/bootstrap.php';

$api = new TokenpassAPI();

// get vars
$promise_id = $argv[1];
$amount     = $argv[2];
if (!$promise_id) { throw new Exception("promise_id is required", 1); }
if (!$amount)     { throw new Exception("amount is required", 1); }

// check
echo "updating $amount\n";
$result = $api->updatePromisedTransaction($promise_id, ['quantity' => $amount, 'expiration' => time()+3600]);


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
