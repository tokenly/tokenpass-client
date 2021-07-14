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
        $config = $this->config['tokenpass'];

        return $this->buildProvider(
            'Tokenly\TokenpassClient\Socialite\Two\TokenpassProvider', $config
        );
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
      if(!isset($config['redirect_uri']) AND isset($config['redirect'])){
        $config['redirect_uri'] = $config['redirect'];
      }
      $provider = new $provider(
          request(), $config['client_id'],
          $config['client_secret'], $config['redirect_uri']
      );

      if(isset($config['tokenpass_url'])){
        $provider->setBaseURL($config['tokenpass_url']);
      }

      return $provider;
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

}
