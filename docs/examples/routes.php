<?php

// The welcome page for the user that requires a logged in user
$router->get('/account/welcome', 'Account\AccountController@welcome');

// routes for logging in and logging out
$router->get('/account/login', 'Account\AccountController@login');
$router->get('/account/logout', 'Account\AccountController@logout');

// This is a route to sync the user with their Tokenpass information
//   Redirect the user here to update their local user information with their Tokenpass information
$router->get('/account/sync', 'Account\AccountController@sync');

// oAuth handlers
$router->get('/account/authorize', 'Account\AccountController@redirectToProvider');
$router->get('/account/authorize/callback', 'Account\AccountController@handleProviderCallback');

