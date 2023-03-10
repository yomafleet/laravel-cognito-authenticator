<?php

namespace Yomafleet\CognitoAuthenticator\Contracts;

use Yomafleet\CognitoAuthenticator\Contracts\TokenContract;

interface TokenFactoryContract
{
    /**
     * Create an instance of TokenContract.
     *
     * @param  array  $claims
     * @param  array  $requiredClaims
     * @return \Yomafleet\CognitoAuthenticator\Contracts\TokenContract
     * @throws \Yomafleet\CognitoAuthenticator\Exceptions\TokenException
     */
    public function create(array $claims, array $requiredClaims = []): TokenContract;
}
