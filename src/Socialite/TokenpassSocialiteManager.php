<?php

namespace Tokenly\TokenpassClient\Socialite;

use Laravel\Socialite\SocialiteManager;

class TokenpassSocialiteManager extends SocialiteManager
{

    /**
     * Create an instance of the specified driver.
     *
     * @return \Laravel\Socialite\Two\AbstractProvider
     */
    protected function createTokenpassDriver()
    {
        $config = $this->app['config']['tokenpass'];

        return $this->buildProvider(
            'Tokenly\TokenpassClient\Socialite\Two\TokenpassProvider', $config
        );
    }

    /**
     * Get the default driver name.
     *
     * @throws \InvalidArgumentException
     *
     * @return string
     */
    public function getDefaultDriver()
    {
        return 'tokenpass';
    }

    /**
     * Build an OAuth 2 provider instance.
     *
     * @param  string  $provider
     * @param  array  $config
     * @return \Laravel\Socialite\Two\AbstractProvider
     */
    public function buildProvider($provider, $config)
    {
        $provider = new $provider(
            $this->app['request'], $config['client_id'],
            $config['client_secret'], $config['redirect']
        );

        $provider->setBaseURL($config['base_url']);

        return $provider;
    }

}
