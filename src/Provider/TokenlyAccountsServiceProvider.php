<?php

namespace Tokenly\AccountsClient\Provider;

use Exception;
use Illuminate\Support\ServiceProvider;
use Tokenly\AccountsClient\Socialite\TokenlyAccountsSocialiteManager;
use Tokenly\AccountsClient\TokenlyAccounts;

/**
* 
*/
class TokenlyAccountsServiceProvider extends ServiceProvider
{
    
    public function boot() {
        $config_source = realpath(__DIR__.'/../../config/tokenlyaccounts.php');
        $this->publishes([$config_source => config_path('tokenlyaccounts.php')], 'config');
    }

    public function register() {
        $this->app->bind('tokenly-accounts', function($app) {
            return new TokenlyAccounts();
        });

        $this->app->bind('Laravel\Socialite\Contracts\Factory', function ($app) {
            return new TokenlyAccountsSocialiteManager($app);
        });
    }

    /**
     * Get the services provided by the provider.
     *
     * @return array
     */
    public function provides()
    {
        return ['Laravel\Socialite\Contracts\Factory'];
    }

}