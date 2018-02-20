<?php

namespace Tokenly\TokenpassClient\Events;

use App\Models\User;

class TokenpassUserSyncedEvent
{

    public $user;

    /**
     * Create a new event instance.
     *
     * @return void
     */
    public function __construct(User $user)
    {
        $this->user = $user;
    }

}
