<?php

namespace Tokenly\TokenpassClient\Socialite\Two;

use Exception;
use Laravel\Socialite\Two\AbstractProvider;
use Laravel\Socialite\Two\ProviderInterface;
use Laravel\Socialite\Two\User;
use GuzzleHttp\Client;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use Laravel\Socialite\Contracts\Provider as ProviderContract;

class TokenpassProvider extends AbstractProvider implements ProviderInterface
{
    /**
     * The scopes being requested.
     *
     * @var array
     */
    protected $scopes = ['user', 'tca'];

    protected $base_url = 'https://tokenpass.tokenly.com';

    public function setBaseURL($base_url) {
        $this->base_url = $base_url;
    }


    /**
     * {@inheritdoc}
     */
    protected function getAuthUrl($state)
    {
        return $this->buildAuthUrlFromBase($this->base_url.'/oauth/authorize', $state);
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenUrl()
    {
        return $this->base_url.'/oauth/access-token';
    }

    /**
     * {@inheritdoc}
     */
    protected function getUserByToken($token)
    {
        $userUrl = $this->base_url.'/oauth/user?access_token='.$token;

        $response = $this->getHttpClient()->get(
            $userUrl, $this->getRequestOptions()
        );

        $user = json_decode($response->getBody(), true);

        return $user;
    }

    /**
     * {@inheritdoc}
     */
    public function getUserByExistingToken($token) {
        $user = $this->mapUserToObject($this->getUserByToken($token));
        return $user->setToken($token);
    }



    /**
     * {@inheritdoc}
     */
    protected function mapUserToObject(array $user)
    {
        return (new User)->setRaw($user)->map([
            'id'       => $user['id'],
            'username' => $user['username'],
            'name'     => array_get($user, 'name'),
            'email'    => array_get($user, 'email'),
        ]);
    }


    /**
     * Get the POST fields for the token request.
     *
     * @param  string  $code
     * @return array
     */
    protected function getTokenFields($code)
    {
        return array_add(
            parent::getTokenFields($code), 'grant_type', 'authorization_code'
        );
    }


    /**
     * Get the default options for an HTTP request.
     *
     * @return array
     */
    protected function getRequestOptions()
    {
        return [
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function user()
    {
        if ($this->user) {
            return $this->user;
        }

        if ($this->hasInvalidState()) {
            //temp disable, causing weird errors
            //throw new InvalidStateException;
        }

        $response = $this->getAccessTokenResponse($this->getCode());

        $this->user = $this->mapUserToObject($this->getUserByToken(
            $token = Arr::get($response, 'access_token')
        ));

        return $this->user->setToken($token)
                    ->setRefreshToken(Arr::get($response, 'refresh_token'))
                    ->setExpiresIn(Arr::get($response, 'expires_in'));
    }

}
