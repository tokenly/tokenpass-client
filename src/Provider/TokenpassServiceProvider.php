<?php

namespace Tokenly\TokenpassClient\Provider;

use Illuminate\Support\ServiceProvider;
use Tokenly\TokenpassClient\Console\MakeTokenpassAuthCommand;
use Tokenly\TokenpassClient\Contracts\TokenpassUserRespositoryContract;
use Tokenly\TokenpassClient\Socialite\TokenpassSocialiteManager;
use Tokenly\TokenpassClient\TokenpassAPI;

/**
 *
 */
class TokenpassServiceProvider extends ServiceProvider
{

    public function register()
    {
        // bind classes
        $this->app->bind(TokenpassAPI::class, function ($app) {
            $config = config('tokenpass');
            return new TokenpassAPI($config['client_id'], $config['client_secret'], $config['privileged_client_id'], $config['privileged_client_secret'], $config['tokenpass_url'], $config['redirect_uri'], $config['oauth_client_id'], $config['oauth_client_secret']);
        });


        // extend the Socialite Factory to add our Socialite Manager
        $this->app->extend('Laravel\Socialite\Contracts\Factory', function($service, $app) {
            return new TokenpassSocialiteManager($app);
        });

        // bind default TokenpassUserRespositoryContract
        if (!$this->app->bound(TokenpassUserRespositoryContract::class)) {
            $this->app->bind(TokenpassUserRespositoryContract::class, 'App\Repositories\UserRepository');
        }
    }

    public function boot()
    {
        // config
        $config_source = __DIR__ . '/../../config/tokenpass.php';
        $this->mergeConfigFrom($config_source, 'tokenpass');
        $this->publishes([$config_source => config_path('tokenpass.php')], 'tokenpass');

        // console commands
        if ($this->app->runningInConsole()) {
            $this->commands([
                MakeTokenpassAuthCommand::class,
            ]);
        }

        // migrations
        $this->loadMigrationsFrom(__DIR__ . '/../../migrations');

        // routes
        $this->loadRoutesFrom(__DIR__ . '/../../routes/tokenpass-routes.php');
    }

}
