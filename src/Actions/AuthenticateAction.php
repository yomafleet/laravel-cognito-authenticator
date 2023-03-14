<?php

namespace Yomafleet\CognitoAuthenticator\Actions;

use Yomafleet\CognitoAuthenticator\Contracts\AuthenticableContract;

class AuthenticateAction
{
    /** @var \Yomafleet\CognitoAuthenticator\Contracts\AuthenticableContract */
    protected $authenticable;

    public function __construct(AuthenticableContract $authenticable)
    {
        $this->authenticable = $authenticable;
    }

    /**
     * Authenticate a user via cognito
     *
     * @param string $identifier
     * @param string $password
     * @return \Aws\Result
     */
    public function __invoke($identifier, $password)
    {
        return $this->authenticate($identifier, $password);
    }

    /**
     * Authenticate a user via cognito
     *
     * @param string $identifier
     * @param string $password
     * @return \Aws\Result
     */
    public function authenticate($identifier, $password)
    {
        return $this->authenticable->authenticate($identifier, $password);
    }
}
