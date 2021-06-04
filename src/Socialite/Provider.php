<?php

namespace Tokenly\TokenpassClient\Socialite;

use SocialiteProviders\Manager\OAuth2\AbstractProvider;
use SocialiteProviders\Manager\OAuth2\User;

class Provider extends AbstractProvider
{
    /**
     * Unique Provider Identifier.
     */
    public const IDENTIFIER = 'TOKENPASS';

    /**
       * {@inheritdoc}
       */
      protected $scopes = ['user', 'tca'];

      /**
       * {@inheritdoc}
       */
      protected function getAuthUrl($state)
      {
          return $this->buildAuthUrlFromBase(
              env('TOKENPASS_PROVIDER_HOST').'/oauth/authorize',
              $state
          );
      }

      /**
       * {@inheritdoc}
       */
      protected function getTokenUrl()
      {
          return env('TOKENPASS_PROVIDER_HOST').'/oauth/token';
      }

      /**
       * {@inheritdoc}
       */
      protected function getUserByToken($token)
      {
          $response = $this->getHttpClient()->get(
              env('TOKENPASS_PROVIDER_HOST').'/oauth/user',
              [
                  'query' => [
                      'access_token' => $token,
                  ],
              ]
          );

          return json_decode($response->getBody()->getContents(), true);
      }

      /**
       * {@inheritdoc}
       */
      protected function mapUserToObject(array $user)
      {
          return (new User())->setRaw($user)->map([
              'id'       => $user['id'],
              'name'     => $user['name'],
              'email'    => $user['email'],
              'username'    => $user['username']
          ]);
      }

      /**
       * {@inheritdoc}
       */
      protected function getTokenFields($code)
      {
          return array_merge(parent::getTokenFields($code), [
              'grant_type' => 'authorization_code',
          ]);
      }
}
