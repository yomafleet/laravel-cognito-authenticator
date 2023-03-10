<?php

namespace Yomafleet\CognitoAuthenticator\Traits;

use Yomafleet\CognitoAuthenticator\Models\CognitoUser;

trait HasCognitoSub
{
    /**
     * Get the user's image.
     */
    public function cognito()
    {
        return $this->morphOne(CognitoUser::class, 'subable');
    }
}
