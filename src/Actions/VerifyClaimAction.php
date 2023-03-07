<?php

namespace Yomafleet\CognitoAuthenticator\Actions;

use Yomafleet\CognitoAuthenticator\Contracts\TokenContract;
use Yomafleet\CognitoAuthenticator\Contracts\UserPoolContract;
use Yomafleet\CognitoAuthenticator\Exceptions\InvalidClaimsException;

class VerifyClaimAction
{
    /** @var \Yomafleet\CognitoAuthenticator\Contracts\TokenContract */
    protected $token;

    /** @var \Yomafleet\CognitoAuthenticator\Contracts\UserPoolContract */
    protected $pool;

    /**
     * Create a new instance.
     *
     * @param \Yomafleet\CognitoAuthenticator\Contracts\TokenContract $token
     * @param  \Yomafleet\CognitoAuthenticator\Contracts\UserPoolContract  $pool
     */
    public function __construct(TokenContract $token, UserPoolContract $pool)
    {
        $this->token = $token;
        $this->pool = $pool;
    }

    /**
     * Verify the claims contained in a token.
     *
     * @return \Yomafleet\CognitoAuthenticator\Contracts\TokenContract
     * @throws \Yomafleet\CognitoAuthenticator\Exceptions\InvalidClaimsException
     */
    public function __invoke(): TokenContract
    {
        if ($this->pool->hasValidClaims($this->token)) {
            return $this->token;
        }

        throw new InvalidClaimsException($this->pool->getClaimsError($this->token));
    }
}
