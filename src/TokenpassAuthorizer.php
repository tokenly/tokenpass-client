<?php

namespace Tokenly\TokenpassClient;

use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use Laravel\Socialite\Facades\Socialite;
use Laravel\Socialite\Two\InvalidStateException;
use Tokenly\LaravelEventLog\Facade\EventLog;
use Tokenly\TokenpassClient\Contracts\TokenpassUserRespositoryContract;
use Tokenly\TokenpassClient\Events\TokenpassUserCreatedEvent;
use Tokenly\TokenpassClient\Exception\TokenpassAuthorizationException;
use Tokenly\TokenpassClient\TokenpassAPI;

/**
 * Tokenpass authorization handler
 */
class TokenpassAuthorizer
{

    public function __construct(TokenpassAPI $tokenpass_api, TokenpassUserRespositoryContract $user_repository)
    {
        $this->tokenpass_api = $tokenpass_api;
        $this->user_repository = $user_repository;
    }

    /**
     * Obtain the user information from Tokenpass.
     *
     * This is the route called after Tokenpass has granted (or denied) permission to this application
     * This application is now responsible for loading the user information from Tokenpass and storing
     * it in the local user database.
     *
     * @return Response
     */
    public function handleProviderCallback(Request $request)
    {

        try {
            // check for an error returned from Tokenpass
            list($error_code, $error_description) = $this->extractErrorFromRequest($request);
            if ($error_description !== null) {
                EventLog::logError('tokenpass.authFailed', ['errorCode' => $error_code, 'errorMessage' => $error_description]);
                throw new TokenpassAuthorizationException($error_description, 1);
            }

            // retrieve the user from Tokenpass
            $oauth_user = Socialite::user();

            // get all the properties from the oAuth user object
            $tokenly_uuid = $oauth_user->id;
            $oauth_token = $oauth_user->token;
            $username = $oauth_user->user['username'];
            $name = $oauth_user->user['name'];
            $email = $oauth_user->user['email'];
            $confirmed_email = $oauth_user->user['email_is_confirmed'] ? $email : null;

            // find an existing user based on the credentials provided
            $existing_user = $this->user_repository->findByTokenlyUuid($tokenly_uuid);

            $logged_in_user = null;
            if ($existing_user) {
                // update the user
                $existing_user->update([
                    'tokenly_uuid' => $tokenly_uuid,
                    'oauth_token' => $oauth_token,
                    'name' => $name,
                    'username' => $username,
                    'email' => $email,
                    'confirmed_email' => $confirmed_email,
                ]);

                // login
                Auth::login($existing_user);

                $logged_in_user = $existing_user;
            } else {
                // no user was found - create a new user based on the information we received
                $new_user = $this->user_repository->create([
                    'tokenly_uuid' => $tokenly_uuid,
                    'oauth_token' => $oauth_token,
                    'name' => $name,
                    'username' => $username,
                    'email' => $email,
                    'confirmed_email' => $confirmed_email,
                ]);

                // fire event
                event(new TokenpassUserCreatedEvent($new_user));

                // login
                Auth::login($new_user);

                $logged_in_user = $new_user;
            }

            // done
            return $logged_in_user;

        } catch (TokenpassAuthorizationException $e) {
            throw $e;
        } catch (InvalidStateException $e) {
            throw $e;
        } catch (Exception $e) {
            Log::debug("exception is ".get_class($e));

            // some unexpected error happened
            EventLog::logError('authorization.failed', $e);
            throw new TokenpassAuthorizationException("Failed to authenticate this user", 1);
        }
    }
    public function syncExistingUser($user)
    {

        try {
            $oauth_user = null;
            if ($user['oauth_token']) {
                $oauth_user = Socialite::getUserByExistingToken($user['oauth_token']);
            }

            if ($oauth_user) {
                // get all the properties from the oAuth user object
                $tokenly_uuid = $oauth_user->id;
                $oauth_token = $oauth_user->token;
                $username = $oauth_user->user['username'];
                $name = $oauth_user->user['name'];
                $email = $oauth_user->user['email'];

                // find an existing user based on the credentials provided
                $existing_user = $this->user_repository->findByTokenlyUuid($tokenly_uuid);
                if ($existing_user and $existing_user->id != $user['id']) {
                    throw new Exception("User ID mismatch", 1);
                }
                if (!$existing_user) {
                    throw new Exception("User not found", 1);
                }

                if ($existing_user and $user) {
                    // update
                    $this->user_repository->update($user, [
                        'tokenly_uuid' => $tokenly_uuid,
                        'oauth_token' => $oauth_token,
                        'name' => $name,
                        'username' => $username,
                        'email' => $email,
                    ]);
                }

                $synced = true;
                EventLog::debug('user.sync.success', ['username' => $user['username']]);

                // fire event
                event(new TokenpassUserSyncedEvent($new_user));
            } else {
                // not able to sync this user
                EventLog::debug('user.sync.faled', ['username' => $user['username']]);
                $synced = false;
            }

            return $synced;

        } catch (Exception $e) {
            EventLog::logError('user.sync.error', $e, ['username' => $user['username']]);
            return false;
        }
    }

    // ------------------------------------------------------------------------

    protected function extractErrorFromRequest(Request $request)
    {
        // check for error
        $error_code = $request->get('error');
        $error_description = null;
        if ($error_code) {
            if ($error_code == 'access_denied') {
                $error_description = 'Access was denied.';
            } else {
                $error_description = $request->get('error_description');
            }
            return [$error_code, $error_description];
        }

        // no error
        return [null, null];
    }
}
