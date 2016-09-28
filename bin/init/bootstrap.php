<?php

// 
require __DIR__.'/../../vendor/autoload.php';

if (!function_exists('env')) {
    function env($key, $default=null) {
        $val = getenv($key);
        if ($val === false) {
            $val = $default;
        }
        return $val;
    }
}
