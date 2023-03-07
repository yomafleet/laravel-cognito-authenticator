<?php

namespace Yomafleet\CognitoAuthenticator\Contracts;

use Yomafleet\CognitoAuthenticator\Models\UserPool;

interface UserPoolFactoryContract
{
    /**
     * Create a new UserPool object
     *
     * @param array $clientIds
     * @throws \Illuminate\Validation\UnauthorizedException
     * @return \Yomafleet\CognitoAuthenticator\Models\UserPool
     */
    public function create(array $clientIds = ['']): UserPool;
}
