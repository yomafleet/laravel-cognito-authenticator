<?php

namespace Yomafleet\CognitoAuthenticator\Traits;

use Yomafleet\CognitoAuthenticator\Models\CognitoUser;

trait HasCognitoSub
{
    /**
     * Get the cognito related as relationship.
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphOne
     */
    public function cognito()
    {
        return $this->morphOne(CognitoUser::class, 'subable');
    }
}
