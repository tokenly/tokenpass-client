<?php

namespace Tokenly\TokenpassClient\Socialite;

use SocialiteProviders\Manager\SocialiteWasCalled;

class TokenpassExtendSocialite
{
    /**
     * Register the provider.
     *
     * @param \SocialiteProviders\Manager\SocialiteWasCalled $socialiteWasCalled
     */
    public function handle(SocialiteWasCalled $socialiteWasCalled)
    {
        $socialiteWasCalled->extendSocialite('tokenpass', Provider::class);
    }
}
