<?php

namespace App\Http\Controllers\Account;

use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Laravel\Socialite\Facades\Socialite;
use App\Http\Controllers\Controller;
use App\Models\User;
use Tokenly\AccountsClient\Facade\TokenlyAccounts;

class AccountController extends Controller
{


    /**
     * Show the welcome page or redirect
     */
    public function welcome() {
        // ensure the user is signed in.  If not, then redirect to the login page
        $user = Auth::user();
        if (!$user) { return redirect('/account/login'); }

        return view('account.welcome', ['user' => $user]);
    }



    /**
     * Login or redirect
     */
    public function login() {
        // if the user is already signed in, go straight to the welcome page
        $user = Auth::user();
        if ($user) { return redirect('/account/welcome'); }

        return view('account.login', ['user' => $user]);
    }


    /**
     * Logout
     */
    public function logout() {
        Auth::logout();
        return view('account.loggedout', []);
    }


    /**
     * Redirect the user to Tokenly Accounts to get authorization
     */
    public function redirectToProvider()
    {
        return Socialite::redirect();
    }



    /**
     * Obtain the user information from Accounts.
     * 
     * This is the route called after Tokenly Accounts has granted (or denied) permission to this application
     * This application is now responsible for loading the user information from Tokenly Accounts and storing
     * it in the local user database.
     *
     * @return Response
     */
    public function handleProviderCallback(Request $request)
    {

        try {
            // check for an error returned from Tokenly Accounts
            $error_description = TokenlyAccounts::checkForError($request);
            if ($error_description) {
                return view('authorization-failed', ['error_msg' => $error_description]);
            }


            // retrieve the user from Tokenly Accounts
            $oauth_user = Socialite::user();

            // get all the properties from the oAuth user object
            $tokenly_uuid       = $oauth_user->id;
            $oauth_token        = $oauth_user->token;
            $username           = $oauth_user->user['username'];
            $name               = $oauth_user->user['name'];
            $email              = $oauth_user->user['email'];
            $email_is_confirmed = $oauth_user->user['email_is_confirmed'];

            // find an existing user based on the credentials provided
            $existing_user = User::where('tokenly_uuid', $tokenly_uuid);

            // if an existing user wasn't found, we might need to find a user to merge into
            $mergable_user = ($existing_user ? null : User::where('username', $username)->where('tokenly_uuid', null));

            if ($existing_user) {
                // update the user
                $existing_user->update(['oauth_token' => $oauth_token, 'name' => $name, 'email' => $email, /* etc */ ]);

                // login
                Auth::login($existing_user);
            } else if ($mergable_user) {
                // an existing user was found with a matching username
                //  migrate it to the tokenly accounts control

                if ($mergable_user['tokenly_uuid']) {
                    throw new Exception("Can't merge a user already associated with a different tokenly account", 1);
                }

                // update if needed
                $mergable_user->update(['name' => $name, 'email' => $email, /* etc */ ]);

                // login
                Auth::login($mergable_user);

            } else {
                // no user was found - create a new user based on the information we received
                $new_user = User::create(['tokenly_uuid' => $tokenly_uuid, 'oauth_token' => $oauth_token, 'name' => $name, 'username' => $username, 'email' => $email, /* etc */ ]);

                // login
                Auth::login($mergable_user);
            }


            return redirect('/account/login');

        } catch (Exception $e) {
            // some unexpected error happened
            return view('authorization-failed', ['error_msg' => 'Failed to authenticate this user.']);
        }
    }



    /**
     * Obtain the user information from Tokenly Accounts.
     *
     * And sync it with our local database
     *
     * @return Response
     */
    public function sync(Request $request)
    {

        try {
            $logged_in_user = Auth::user();

            $oauth_user = null;
            if ($logged_in_user['oauth_token']) {
                $oauth_user = Socialite::getUserByExistingToken($logged_in_user['oauth_token']);
            }

            if ($oauth_user) {
                $tokenly_uuid       = $oauth_user->id;
                $oauth_token        = $oauth_user->token;
                $username           = $oauth_user->user['username'];
                $name               = $oauth_user->user['name'];
                $email              = $oauth_user->user['email'];
                $email_is_confirmed = $oauth_user->user['email_is_confirmed'];

                // find an existing user based on the credentials provided
                $existing_user = User::where('tokenly_uuid', $tokenly_uuid);
                if ($existing_user) {
                    // update
                    $existing_user->update(['name' => $name, 'email' => $email, /* etc */ ]);
                }

                $synced = true;
            } else {
                // not able to sync this user
                $synced = false;
            }

            return view('account.sync', ['synced' => $synced, 'user' => $logged_in_user, ]);

        } catch (Exception $e) {
            return view('sync-failed', ['error_msg' => 'Failed to sync this user.']);
        }
    }

}
