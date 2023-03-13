<?php

namespace Yomafleet\CognitoAuthenticator\Contracts;

use Yomafleet\CognitoAuthenticator\Exceptions\TokenException;
use Yomafleet\CognitoAuthenticator\Contracts\UserPoolContract;

interface TokenContract
{
    /**
     * Get all claims.
     *
     * @return array
     */
    public function claims();

    /**
     * Get a claim value for the token.
     *
     * @param  string  $name
     * @return mixed
     */
    public function getClaim($name);

    /**
     * Get a "sub" claim from the token.
     *
     * @throws TokenException
     * @return mixed
     */
    public function getSub();

    /**
     * Get any claim errors relevant to the given UserPool.
     *
     * @param  \Yomafleet\CognitoAuthenticator\Contracts\UserPoolContract  $userPool
     * @return string | null
     */
    public function getClaimsError(UserPoolContract $userPool);
}
