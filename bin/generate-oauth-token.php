#!/usr/bin/env php
<?php

use Tokenly\TokenpassClient\TokenpassAPI;

/*

# Usage:

export TOKENPASS_PROVIDER_HOST=https://tokenpass-stage.tokenly.com
export TOKENPASS_CLIENT_ID=xxxxx
export TOKENPASS_CLIENT_SECRET=xxxxx

./generate-oauth-token.php <step> <code>

*/ 

require __DIR__.'/init/bootstrap.php';

$step = $argv[1];
if (!$step) { throw new Exception("Step is required", 1); }
if ($step == 1) {
    
    $get_vars = [
        'client_id'     => env('TOKENPASS_CLIENT_ID'),
        'redirect_uri'  => 'http://localhost:8000/oauth_callback',
        'scope'         => 'tca,private-address,manage-address,private-balances',
        'response_type' => 'code',
        'state'         => 'foo_'.date("Ymd_His"),
    ];
    $url = env('TOKENPASS_PROVIDER_HOST').'/oauth/authorize?'.http_build_query($get_vars);
    echo "$url\n";
    exit(0);
}

if ($step == 2) {
    $code = $argv[2];
    if (!$code) { throw new Exception("Code is required", 1); }

    $api = new TokenpassAPI();
    $access_token = $api->getOAuthAccessToken($code);

    echo "\$access_token:\n$access_token\n";

    exit(0);
}

exit(1);
