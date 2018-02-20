<?php

namespace Tokenly\TokenpassClient\Events;

use App\Models\User;

class TokenpassUserCreatedEvent
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
