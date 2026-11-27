<?php

namespace Yomafleet\CognitoAuthenticator\Contracts;

interface AuthenticableContract
{
    /**
     * Authenticate a user via cognito
     *
     * @param string $identifier
     * @param string $password
     * @return mixed
     */
    public function authenticate($identifier, $password);
}
