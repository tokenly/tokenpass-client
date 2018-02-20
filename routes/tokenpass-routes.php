<?php

Route::group([
    'prefix'     => config('tokenpass.route_prefix'),
    'middleware' => ['web'],
], function () {
    // routes for logging in and logging out
    Route::get('login', 'Tokenly\TokenpassClient\Http\Controllers\TokenpassAuthController@login')->name('login');
    Route::get('logout', 'Tokenly\TokenpassClient\Http\Controllers\TokenpassAuthController@logout')->name('tokenpass.logout');

    // oAuth handlers
    Route::get('authorize', 'Tokenly\TokenpassClient\Http\Controllers\TokenpassAuthController@redirectToProvider')->name('tokenpass.authorize');
    Route::get('authorize/callback', 'Tokenly\TokenpassClient\Http\Controllers\TokenpassAuthController@handleProviderCallback')->name('tokenpass.authorize-callback');


    // protected routes
    Route::group([
        'middleware' => ['auth'],
    ], function () {
        // The welcome page for the user that requires a logged in user
        Route::get('home', 'Tokenly\TokenpassClient\Http\Controllers\TokenpassAuthController@home')->name('tokenpass.home');

        // This is a route to sync the user with their Tokenpass information
        //   Redirect the user here to update their local user information with their Tokenpass information
        Route::get('sync', 'Tokenly\TokenpassClient\Http\Controllers\TokenpassAuthController@sync')->name('tokenpass.sync');
    });

});
