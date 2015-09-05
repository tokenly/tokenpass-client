<?php

namespace Tokenly\AccountsClient\Facade;

use Exception;
use Illuminate\Support\Facades\Facade;

/**
* 
*/
class TokenlyAccounts extends Facade
{
    
    protected static function getFacadeAccessor() { 
        return 'tokenly-accounts';
    }

}