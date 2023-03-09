<?php

namespace Yomafleet\CognitoAuthenticator;

use Yomafleet\CognitoAuthenticator\Contracts\TokenContract;
use Yomafleet\CognitoAuthenticator\Actions\VerifyClaimAction;
use Yomafleet\CognitoAuthenticator\Contracts\UserPoolContract;
use Yomafleet\CognitoAuthenticator\Contracts\ClaimVerifierContract;

class CognitoClaimVerifier implements ClaimVerifierContract
{
    /** @var \Yomafleet\CognitoAuthenticator\Contracts\UserPoolContract */
    protected $pool;

    /**
     * CognitoClaimVerifier constructor.
     *
     * @param  \Yomafleet\CognitoAuthenticator\Contracts\UserPoolContract  $pool
     */
    public function __construct(UserPoolContract $pool)
    {
        $this->pool = $pool;
    }

    /**
     * {@inheritdoc}
     *
     * @return \Yomafleet\CognitoAuthenticator\Contracts\UserPoolContract
     */
    public function getUserPool(): UserPoolContract
    {
        return $this->pool;
    }

    /**
     * {@inheritdoc}
     *
     * @param  \Yomafleet\CognitoAuthenticator\Contracts\TokenContract  $token
     * @return \Yomafleet\CognitoAuthenticator\Contracts\TokenContract
     *
     * @throws \Yomafleet\CognitoAuthenticator\Exceptions\InvalidClaimsException
     */
    public function verify(TokenContract $token): TokenContract
    {
        $verifier = new VerifyClaimAction($token, $this->getUserPool());

        return $verifier();
    }
}
