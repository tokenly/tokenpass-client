<?php

return [
    // Enter your client id and client secret from Tokenpass here
    'client_id'     => env('TOKENPASS_CLIENT_ID',           'YOUR_TOKENPASS_CLIENT_ID_HERE'),
    'client_secret' => env('TOKENPASS_CLIENT_SECRET',       'YOUR_TOKENPASS_CLIENT_SECRET_HERE'),

    // this is the URL that Tokenpass uses to redirect the user back to your application
    'redirect'      => env('TOKENPASS_REDIRECT_URI',        'https://YourSiteHere.com/account/authorize/callback'),

    // this is the Tokenpass URL
    'base_url'      => rtrim(env('TOKENPASS_PROVIDER_HOST', 'https://tokenpass.tokenly.com'), '/'),
];
