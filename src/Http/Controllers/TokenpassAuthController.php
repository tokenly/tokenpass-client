<?php

namespace Tokenly\TokenpassClient\Http\Controllers;

use Exception;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use Laravel\Socialite\Facades\Socialite;
use Laravel\Socialite\Two\InvalidStateException;
use Tokenly\TokenpassClient\Exception\TokenpassAuthorizationException;
use Tokenly\TokenpassClient\TokenpassAuthorizer;

class TokenpassAuthController extends Controller
{

    public function home()
    {
        return view('home', $this->sharedViewData());
    }

    public function login()
    {
        // is the user logged in?
        if (Auth::user()) {
            // redirect to the home page
        }

        return view('auth/login', $this->sharedViewData());
    }

    public function logout()
    {
        Auth::logout();
        return view('auth/logout', $this->sharedViewData());
    }

    public function sync()
    {
        try {
            // handle callback here
            $user = Auth::user();
            $tokenpass_authorizer->syncExistingUser($user);
            return view('auth/sync', $this->sharedViewData());
        } catch (TokenpassAuthorizationException $e) {
            return view('auth/error', ['errorMessage' => $e->getMessage()] + $this->sharedViewData());
        }
    }

    public function redirectToProvider()
    {
        // set scopes
        Socialite::scopes(explode(',', config('tokenpass.scopes')));

        // and redirect
        return Socialite::redirect();
    }

    public function handleProviderCallback(Request $request, TokenpassAuthorizer $tokenpass_authorizer)
    {
        try {
            // handle callback here
            $logged_in_user = $tokenpass_authorizer->handleProviderCallback($request);

        } catch (InvalidStateException $e) {
            Log::debug("InvalidStateException caught");
            return redirect(route('login'))->withErrors('Could not authenticate at this time.  Please try again.');

        } catch (TokenpassAuthorizationException $e) {
            return view('auth/error', ['errorMessage' => $e->getMessage()] + $this->sharedViewData());
        }

        // logged in successfully
        return redirect()->intended(route('tokenpass.home'));
    }

    protected function sharedViewData()
    {
        return ['user' => Auth::user()];
    }
}
