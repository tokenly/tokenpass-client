<?php

namespace Tokenly\TokenpassClient;

use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Facade;

/**
* 
*/
class Tokenpass
{
    
    function __construct() {
        
    }

    public function checkForError(Request $request) {
        // check for error
        $error_code = $request->get('error');
        if ($error_code) {
            if ($error_code == 'access_denied') {
                $error_description = 'Access was denied.';
            } else {
                $error_description = $request->get('error_description');
            }
            return $error_description;
        }

        // no error
        return null;
    }

}