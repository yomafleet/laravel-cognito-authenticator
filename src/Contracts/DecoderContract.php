<?php

namespace Yomafleet\CognitoAuthenticator\Contracts;

use Yomafleet\CognitoAuthenticator\Contracts\TokenContract;

interface DecoderContract
{
    /**
     * Given a JWT string, decode it. An invalid token
     * will result in a null response - otherwise an array
     * with the result will be returned.
     *
     * @param  string  $token
     * @param  array<string>  $extraRequiredClaims
     * @return TokenContract
     */
    public function decode(string $token, array $extraRequiredClaims = []): TokenContract;
}
