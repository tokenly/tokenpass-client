<?php

/**
 * Instantiator provides utility methods to build objects without invoking their constructors
 *
 * @author Marco Pivetta <ocramius@gmail.com>
 */

namespace Tokenly\TokenpassClient\Contracts;

use Illuminate\Database\Eloquent\Model;

interface TokenpassUserRespositoryContract
{

    public function create($attributes);

    public function update(Model $resource, $attributes);

    public function findByTokenlyUuid($tokenly_uuid);

}
