<?php

namespace Tokenly\TokenpassClient\Facade;

use Exception;
use Illuminate\Support\Facades\Facade;

/**
* 
*/
class Tokenpass extends Facade
{
    
    protected static function getFacadeAccessor() { 
        return '\Tokenly\TokenpassClient\Tokenpass';
    }

}
