#!/usr/bin/env php
<?php

use Tokenly\TokenpassClient\TokenpassAPI;

/*

# Usage:

export TOKENPASS_PROVIDER_HOST=https://tokenpass-stage.tokenly.com
export TOKENPASS_CLIENT_ID=xxxxx
export TOKENPASS_CLIENT_SECRET=xxxxx

./provisional-list-source-addresses.php

*/ 

require __DIR__.'/init/bootstrap.php';

$api = new TokenpassAPI();


echo "getting addresses\n";
$result = $api->getProvisionalSourceList();

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

if($result){
    foreach($result as $source_address){
        $address = $source_address['address'];
        $restricted_assets = $source_address['assets'];
    }
}
