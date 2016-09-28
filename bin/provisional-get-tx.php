#!/usr/bin/env php
<?php

use Tokenly\TokenpassClient\TokenpassAPI;

/*

# Usage:

export TOKENPASS_PROVIDER_HOST=https://tokenpass-stage.tokenly.com
export TOKENPASS_CLIENT_ID=xxxxx
export TOKENPASS_CLIENT_SECRET=xxxxx

./provisional-get-tx.php <promise_id>

*/ 

require __DIR__.'/init/bootstrap.php';

$api = new TokenpassAPI();

// get vars
$promise_id = $argv[1];

// check
echo "Getting provisional tx for promise_id $promise_id\n";
$result = $api->getPromisedTransaction($promise_id);

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
