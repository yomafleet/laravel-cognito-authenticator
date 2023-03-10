<?php

namespace Yomafleet\CognitoAuthenticator\Contracts;

use Yomafleet\CognitoAuthenticator\Contracts\TokenContract;
use Yomafleet\CognitoAuthenticator\Contracts\UserPoolContract;

interface ClaimVerifierContract
{
    /**
     * Verify the claims contained in a token.
     *
     * @param  \Yomafleet\CognitoAuthenticator\Contracts\TokenContract  $token
     * @return \Yomafleet\CognitoAuthenticator\Contracts\TokenContract
     *
     * @throws \Yomafleet\CognitoAuthenticator\Exceptions\InvalidClaimsException
     */
    public function verify(TokenContract $token): TokenContract;

    /**
     * Get the user pool that tokens are verified against.
     *
     * @return \Yomafleet\CognitoAuthenticator\Contracts\UserPoolContract
     */
    public function getUserPool(): UserPoolContract;
}
